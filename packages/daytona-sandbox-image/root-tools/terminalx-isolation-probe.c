#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define TERMINALX_UID ((uid_t)10001)
#define TERMINALX_GID ((gid_t)10001)
#define EXPECTED_AGENT_BOUNDING_SET UINT64_C(0x00000000000000e1)
#define MAX_PROCESSES 512
#define MAX_HELPERS_PER_KIND 32
#define MAX_ROOT_PROCESSES 128
#define MAX_ENVIRONMENT_BYTES (64 * 1024)
#define MAX_OUTPUT_BYTES (64 * 1024)

static const char *const INIT_PATH = "/usr/local/bin/terminalx-sandbox-init";
static const char *const DAYTONA_PATH = "/usr/local/bin/daytona";
static const char *const NODE_PATH = "/usr/local/bin/node";
static const char *const RUNTIME_ROOT = "/run/terminalx-root";
static const char *const RELAY_PATH =
    "/usr/local/libexec/terminalx/terminalx-supervisor-relay";
static const char *const BOOTSTRAP_PATH =
    "/usr/local/libexec/terminalx/terminalx-assignment-bootstrap";
static const char *const DEPLOYMENT_BINDING_INSTALL_PATH =
    "/usr/local/libexec/terminalx/terminalx-deployment-binding-install";
static const char *const EFFECT_PATH =
    "/usr/local/libexec/terminalx/terminalx-effect-enforcer";
static const char *const PEERCRED_PATH =
    "/usr/local/libexec/terminalx/terminalx-peercred";
static const char *const PROBE_PATH =
    "/usr/local/libexec/terminalx/terminalx-isolation-probe";
static const char *const SANDBOX_HOSTNAME = "terminalx-sandbox";

extern char **environ;

struct process_state {
  pid_t pid;
  pid_t parent_pid;
  uid_t uid[4];
  gid_t gid[4];
  uint64_t cap_inheritable;
  uint64_t cap_permitted;
  uint64_t cap_effective;
  uint64_t cap_bounding;
  uint64_t cap_ambient;
  int no_new_privileges;
  bool supplementary_groups_empty;
};

struct root_inventory {
  size_t process_count;
  size_t probe_count;
  size_t relay_count;
  size_t bootstrap_count;
  size_t deployment_installer_count;
  size_t peercred_count;
  size_t effect_count;
  pid_t supervisor_child_parents[MAX_HELPERS_PER_KIND * 2];
  size_t supervisor_child_parent_count;
  bool all_allowed;
  bool all_capabilities_match;
};

struct agent_aggregate {
  size_t process_count;
  uint64_t cap_inheritable;
  uint64_t cap_permitted;
  uint64_t cap_effective;
  uint64_t cap_bounding;
  uint64_t cap_ambient;
  bool all_ids_match;
  bool all_no_new_privileges;
  bool all_supplementary_groups_empty;
};

struct measured_path {
  const char *path;
  const char *type;
  uid_t uid;
  gid_t gid;
  mode_t mode;
  nlink_t nlink;
};

struct denial_result {
  uint8_t private_key_read_denied;
  uint8_t private_key_write_denied;
  uint8_t root_runtime_write_denied;
  uint8_t root_state_write_denied;
  uint8_t signal_init_denied;
  uint8_t signal_supervisor_denied;
  uint8_t agent_environment_safe;
};

struct output_buffer {
  char bytes[MAX_OUTPUT_BYTES];
  size_t length;
  bool failed;
};

static const struct {
  const char *path;
  mode_t mode;
} EXECUTABLES[] = {
    {"/usr/local/bin/daytona", 0555},
    {"/usr/local/bin/node", 0555},
    {"/usr/local/bin/terminalx-sandbox-init", 0555},
    {"/usr/local/libexec/terminalx/terminalx-assignment-bootstrap", 0555},
    {"/usr/local/libexec/terminalx/terminalx-daytona-supervisor", 0555},
    {"/usr/local/libexec/terminalx/terminalx-deployment-binding-install", 0555},
    {"/usr/local/libexec/terminalx/terminalx-effect-enforcer", 0500},
    {"/usr/local/libexec/terminalx/terminalx-isolation-probe", 0555},
    {"/usr/local/libexec/terminalx/terminalx-peercred", 0500},
    {"/usr/local/libexec/terminalx/terminalx-supervisor-relay", 0555},
};

static const struct {
  const char *path;
  const char *type;
  mode_t mode;
} PRIVATE_PATHS[] = {
    {"/etc/terminalx", "directory", 0500},
    {"/run/terminalx-private", "directory", 0700},
    {"/run/terminalx-private/daytona-daemon.sock", "socket", 0600},
    {"/run/terminalx-root", "directory", 0700},
    {"/run/terminalx-root/assignment", "directory", 0700},
    {"/run/terminalx-root/assignment/effect-enforcer-key.pk8", "file", 0600},
    {"/run/terminalx-root/assignment/observation-key.pk8", "file", 0600},
    {"/run/terminalx-root/assignment/state-signing.pk8", "file", 0600},
    {"/run/terminalx-root/deployment-binding.json", "file", 0600},
    {"/var/lib/terminalx-supervisor", "directory", 0700},
};

static const char *const PRIVATE_KEYS[] = {
    "/run/terminalx-root/assignment/effect-enforcer-key.pk8",
    "/run/terminalx-root/assignment/observation-key.pk8",
    "/run/terminalx-root/assignment/state-signing.pk8",
};

static bool validate_fixed_environment(void) {
  char **entry;
  size_t count = 0;
  unsigned int found = 0;
  for (entry = environ; entry != NULL && *entry != NULL; entry++) {
    count++;
    if (strncmp(*entry, "DAYTONA_SANDBOX_ID=", 19) == 0 &&
        strlen(*entry + 19) == 36) {
      const char *value = *entry + 19;
      size_t index;
      bool valid = value[8] == '-' && value[13] == '-' && value[18] == '-' &&
                   value[23] == '-' && value[14] == '4' &&
                   strchr("89ab", value[19]) != NULL;
      for (index = 0; valid && index < 36; index++) {
        if (index == 8 || index == 13 || index == 18 || index == 23) continue;
        valid = (value[index] >= '0' && value[index] <= '9') ||
                (value[index] >= 'a' && value[index] <= 'f');
      }
      if (!valid) return false;
      found |= 1U;
    } else if (strncmp(*entry, "DAYTONA_SANDBOX_SNAPSHOT=", 25) == 0 &&
               strlen(*entry + 25) >= 1 && strlen(*entry + 25) <= 300) {
      const unsigned char *value = (const unsigned char *)(*entry + 25);
      while (*value != '\0') {
        if (*value <= 0x20 || *value == 0x7f) return false;
        value++;
      }
      found |= 2U;
    } else if (strcmp(*entry, "DAYTONA_SANDBOX_USER=terminalx") == 0) {
      found |= 4U;
    } else {
      return false;
    }
  }
  return count == 3 && found == 7U;
}

static bool validate_fixed_hostname(void) {
  char hostname[257];
  memset(hostname, 0, sizeof(hostname));
  if (gethostname(hostname, sizeof(hostname) - 1) != 0) {
    return false;
  }
  hostname[sizeof(hostname) - 1] = '\0';
  return strcmp(hostname, SANDBOX_HOSTNAME) == 0;
}

static bool parse_hex_capability(const char *value, uint64_t *output) {
  char *end = NULL;
  unsigned long long parsed;
  errno = 0;
  parsed = strtoull(value, &end, 16);
  if (errno != 0 || end == value || (*end != '\n' && *end != '\0')) {
    return false;
  }
  *output = (uint64_t)parsed;
  return true;
}

static bool read_process_state(pid_t pid, struct process_state *output) {
  char path[64];
  char line[512];
  FILE *status;
  unsigned int fields = 0;
  memset(output, 0, sizeof(*output));
  output->pid = pid;
  if (snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid) < 1) {
    return false;
  }
  status = fopen(path, "re");
  if (status == NULL) {
    return false;
  }
  while (fgets(line, sizeof(line), status) != NULL) {
    unsigned int a, b, c, d;
    if (sscanf(line, "Uid:\t%u\t%u\t%u\t%u", &a, &b, &c, &d) == 4) {
      output->uid[0] = (uid_t)a;
      output->uid[1] = (uid_t)b;
      output->uid[2] = (uid_t)c;
      output->uid[3] = (uid_t)d;
      fields |= 1U;
    } else if (sscanf(line, "PPid:\t%u", &a) == 1 && a <= INT32_MAX) {
      output->parent_pid = (pid_t)a;
      fields |= 512U;
    } else if (sscanf(line, "Gid:\t%u\t%u\t%u\t%u", &a, &b, &c, &d) == 4) {
      output->gid[0] = (gid_t)a;
      output->gid[1] = (gid_t)b;
      output->gid[2] = (gid_t)c;
      output->gid[3] = (gid_t)d;
      fields |= 2U;
    } else if (strncmp(line, "CapInh:\t", 8) == 0 &&
               parse_hex_capability(line + 8, &output->cap_inheritable)) {
      fields |= 4U;
    } else if (strncmp(line, "CapPrm:\t", 8) == 0 &&
               parse_hex_capability(line + 8, &output->cap_permitted)) {
      fields |= 8U;
    } else if (strncmp(line, "CapEff:\t", 8) == 0 &&
               parse_hex_capability(line + 8, &output->cap_effective)) {
      fields |= 16U;
    } else if (strncmp(line, "CapBnd:\t", 8) == 0 &&
               parse_hex_capability(line + 8, &output->cap_bounding)) {
      fields |= 32U;
    } else if (strncmp(line, "CapAmb:\t", 8) == 0 &&
               parse_hex_capability(line + 8, &output->cap_ambient)) {
      fields |= 64U;
    } else if (sscanf(line, "NoNewPrivs:\t%d", &output->no_new_privileges) == 1) {
      fields |= 128U;
    } else if (strncmp(line, "Groups:\t", 8) == 0) {
      const char *value = line + 8;
      while (*value == ' ' || *value == '\t') value++;
      output->supplementary_groups_empty = *value == '\n' || *value == '\0';
      fields |= 256U;
    }
  }
  if (fclose(status) != 0) {
    return false;
  }
  return fields == 1023U;
}

static bool read_executable(pid_t pid, char *output, size_t capacity) {
  char path[64];
  ssize_t length;
  if (snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid) < 1) {
    return false;
  }
  length = readlink(path, output, capacity - 1);
  if (length < 1 || (size_t)length >= capacity - 1) {
    return false;
  }
  output[length] = '\0';
  return true;
}

static bool supervisor_command_line_matches(pid_t pid) {
  static const char expected[] =
      "/usr/local/bin/node\0"
      "/usr/local/libexec/terminalx/terminalx-daytona-supervisor\0"
      "/run/terminalx-root\0"
      "/run/terminalx-root/assignment/bootstrap.json\0";
  char path[64];
  char actual[sizeof(expected) + 1];
  int descriptor;
  ssize_t length;
  if (snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid) < 1) {
    return false;
  }
  descriptor = open(path, O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return false;
  }
  length = read(descriptor, actual, sizeof(actual));
  (void)close(descriptor);
  return length == (ssize_t)(sizeof(expected) - 1) &&
         memcmp(actual, expected, sizeof(expected) - 1) == 0;
}

static bool daemon_command_line_matches(pid_t pid) {
  static const char expected[] =
      "/usr/local/bin/daytona\0"
      "--terminalx-toolbox-listener-fd=3\0";
  char path[64];
  char actual[sizeof(expected) + 1];
  int descriptor;
  ssize_t length;
  if (snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid) < 1) {
    return false;
  }
  descriptor = open(path, O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return false;
  }
  length = read(descriptor, actual, sizeof(actual));
  (void)close(descriptor);
  return length == (ssize_t)(sizeof(expected) - 1) &&
         memcmp(actual, expected, sizeof(expected) - 1) == 0;
}

static bool fixed_node_helper_command_line_matches(pid_t pid, const char *helper_path) {
  char expected[512];
  char actual[sizeof(expected)];
  char path[64];
  int expected_length;
  int descriptor;
  ssize_t length;
  expected_length = snprintf(expected, sizeof(expected), "%s%c%s%c", NODE_PATH, '\0',
                             helper_path, '\0');
  if (expected_length < 1 || (size_t)expected_length >= sizeof(expected) ||
      snprintf(path, sizeof(path), "/proc/%ld/cmdline", (long)pid) < 1) {
    return false;
  }
  descriptor = open(path, O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return false;
  }
  length = read(descriptor, actual, (size_t)expected_length + 1U);
  (void)close(descriptor);
  return length == expected_length &&
         memcmp(actual, expected, (size_t)expected_length) == 0;
}

static bool all_process_ids(const struct process_state *state, uid_t uid, gid_t gid) {
  size_t index;
  for (index = 0; index < 4; index++) {
    if (state->uid[index] != uid || state->gid[index] != gid) {
      return false;
    }
  }
  return true;
}

static bool root_capabilities_match(const struct process_state *state) {
  return state->cap_ambient == 0 &&
         state->cap_bounding == EXPECTED_AGENT_BOUNDING_SET &&
         state->cap_effective == EXPECTED_AGENT_BOUNDING_SET &&
         state->cap_inheritable == 0 &&
         state->cap_permitted == EXPECTED_AGENT_BOUNDING_SET &&
         state->no_new_privileges == 1;
}

static bool any_process_uid(const struct process_state *state, uid_t uid) {
  size_t index;
  for (index = 0; index < 4; index++) {
    if (state->uid[index] == uid) return true;
  }
  return false;
}

static void inventory_root_process(const struct process_state *state,
                                   const char *executable,
                                   bool supervisor_match,
                                   struct root_inventory *inventory) {
  bool allowed = false;
  inventory->process_count++;
  inventory->all_capabilities_match =
      inventory->all_capabilities_match && all_process_ids(state, 0, 0) &&
      root_capabilities_match(state);
  if (strcmp(executable, INIT_PATH) == 0 || supervisor_match) {
    allowed = true;
  } else if (state->pid == getpid() && strcmp(executable, PROBE_PATH) == 0) {
    inventory->probe_count++;
    allowed = true;
  } else if (strcmp(executable, PEERCRED_PATH) == 0) {
    inventory->peercred_count++;
    allowed = true;
    if (inventory->supervisor_child_parent_count <
        sizeof(inventory->supervisor_child_parents) /
            sizeof(inventory->supervisor_child_parents[0])) {
      inventory->supervisor_child_parents[inventory->supervisor_child_parent_count++] =
          state->parent_pid;
    } else {
      allowed = false;
    }
  } else if (strcmp(executable, EFFECT_PATH) == 0 ||
             (strcmp(executable, NODE_PATH) == 0 &&
              fixed_node_helper_command_line_matches(state->pid, EFFECT_PATH))) {
    inventory->effect_count++;
    allowed = true;
    if (inventory->supervisor_child_parent_count <
        sizeof(inventory->supervisor_child_parents) /
            sizeof(inventory->supervisor_child_parents[0])) {
      inventory->supervisor_child_parents[inventory->supervisor_child_parent_count++] =
          state->parent_pid;
    } else {
      allowed = false;
    }
  } else if (strcmp(executable, NODE_PATH) == 0 &&
             fixed_node_helper_command_line_matches(state->pid, RELAY_PATH)) {
    inventory->relay_count++;
    allowed = true;
  } else if (strcmp(executable, NODE_PATH) == 0 &&
             fixed_node_helper_command_line_matches(state->pid, BOOTSTRAP_PATH)) {
    inventory->bootstrap_count++;
    allowed = true;
  } else if (strcmp(executable, NODE_PATH) == 0 &&
             fixed_node_helper_command_line_matches(
                 state->pid, DEPLOYMENT_BINDING_INSTALL_PATH)) {
    inventory->deployment_installer_count++;
    allowed = true;
  }
  inventory->all_allowed = inventory->all_allowed && allowed;
}

static bool scan_processes(struct process_state *init,
                           struct process_state *daemon,
                           struct process_state *supervisor,
                           struct agent_aggregate *agent) {
  DIR *directory = opendir("/proc");
  struct dirent *entry;
  size_t inspected = 0;
  unsigned int init_matches = 0;
  unsigned int daemon_matches = 0;
  unsigned int supervisor_matches = 0;
  struct root_inventory root;
  if (directory == NULL) {
    return false;
  }
  memset(init, 0, sizeof(*init));
  memset(daemon, 0, sizeof(*daemon));
  memset(supervisor, 0, sizeof(*supervisor));
  memset(agent, 0, sizeof(*agent));
  memset(&root, 0, sizeof(root));
  agent->all_ids_match = true;
  agent->all_no_new_privileges = true;
  agent->all_supplementary_groups_empty = true;
  root.all_allowed = true;
  root.all_capabilities_match = true;
  for (;;) {
    char *end = NULL;
    long parsed;
    struct process_state state;
    char executable[512];
    errno = 0;
    entry = readdir(directory);
    if (entry == NULL) {
      if (errno != 0) {
        (void)closedir(directory);
        return false;
      }
      break;
    }
    if (entry->d_name[0] < '1' || entry->d_name[0] > '9') {
      continue;
    }
    errno = 0;
    parsed = strtol(entry->d_name, &end, 10);
    if (errno != 0 || end == entry->d_name || *end != '\0' || parsed < 1 ||
        parsed > INT32_MAX || ++inspected > MAX_PROCESSES) {
      (void)closedir(directory);
      return false;
    }
    if (!read_process_state((pid_t)parsed, &state) ||
        !read_executable((pid_t)parsed, executable, sizeof(executable))) {
      if (errno == ENOENT) {
        errno = 0;
        continue;
      }
      (void)closedir(directory);
      return false;
    }
    if (strcmp(executable, INIT_PATH) == 0) {
      *init = state;
      init_matches++;
    }
    if (strcmp(executable, DAYTONA_PATH) == 0 &&
        daemon_command_line_matches(state.pid)) {
      *daemon = state;
      daemon_matches++;
    }
    {
      bool supervisor_match =
          strcmp(executable, NODE_PATH) == 0 &&
          supervisor_command_line_matches(state.pid);
      if (supervisor_match) {
        *supervisor = state;
        supervisor_matches++;
      }
      if (any_process_uid(&state, 0)) {
        inventory_root_process(&state, executable, supervisor_match, &root);
      }
    }
    if (state.uid[0] == TERMINALX_UID || state.uid[1] == TERMINALX_UID ||
        state.uid[2] == TERMINALX_UID || state.uid[3] == TERMINALX_UID) {
      agent->process_count++;
      agent->all_ids_match =
          agent->all_ids_match && all_process_ids(&state, TERMINALX_UID, TERMINALX_GID);
      agent->all_no_new_privileges =
          agent->all_no_new_privileges && state.no_new_privileges == 1;
      agent->all_supplementary_groups_empty =
          agent->all_supplementary_groups_empty && state.supplementary_groups_empty;
      agent->cap_inheritable |= state.cap_inheritable;
      agent->cap_permitted |= state.cap_permitted;
      agent->cap_effective |= state.cap_effective;
      agent->cap_bounding |= state.cap_bounding;
      agent->cap_ambient |= state.cap_ambient;
    }
  }
  if (closedir(directory) != 0) {
    return false;
  }
  if (supervisor_matches == 1) {
    size_t index;
    for (index = 0; index < root.supervisor_child_parent_count; index++) {
      if (root.supervisor_child_parents[index] != supervisor->pid) {
        return false;
      }
    }
  } else if (root.supervisor_child_parent_count != 0) {
    return false;
  }
  return init_matches == 1 && daemon_matches == 1 && supervisor_matches == 1 &&
         root.process_count >= 3 && root.process_count <= MAX_ROOT_PROCESSES &&
         root.probe_count == 1 && root.relay_count <= MAX_HELPERS_PER_KIND &&
         root.bootstrap_count <= 1 && root.deployment_installer_count <= 1 &&
         root.peercred_count <= MAX_HELPERS_PER_KIND &&
         root.effect_count <= MAX_HELPERS_PER_KIND && root.all_allowed &&
         root.all_capabilities_match &&
         agent->process_count >= 1 && agent->all_ids_match &&
         agent->all_no_new_privileges && agent->all_supplementary_groups_empty &&
         agent->cap_inheritable == 0 &&
         agent->cap_permitted == 0 && agent->cap_effective == 0 &&
         agent->cap_bounding == EXPECTED_AGENT_BOUNDING_SET &&
         agent->cap_ambient == 0 && all_process_ids(init, 0, 0) &&
         all_process_ids(supervisor, 0, 0) &&
         root_capabilities_match(init) && root_capabilities_match(supervisor) &&
         all_process_ids(daemon, TERMINALX_UID, TERMINALX_GID) &&
         daemon->cap_inheritable == 0 && daemon->cap_permitted == 0 &&
         daemon->cap_effective == 0 &&
         daemon->cap_bounding == EXPECTED_AGENT_BOUNDING_SET &&
         daemon->cap_ambient == 0 && daemon->no_new_privileges == 1 &&
         daemon->supplementary_groups_empty;
}

static bool measure_fixed_paths(struct measured_path *private_paths,
                                struct measured_path *executables) {
  size_t index;
  struct stat status;
  for (index = 0; index < sizeof(PRIVATE_PATHS) / sizeof(PRIVATE_PATHS[0]); index++) {
    bool is_file = strcmp(PRIVATE_PATHS[index].type, "file") == 0;
    bool is_socket = strcmp(PRIVATE_PATHS[index].type, "socket") == 0;
    char resolved[4096];
    if (realpath(PRIVATE_PATHS[index].path, resolved) == NULL ||
        strcmp(resolved, PRIVATE_PATHS[index].path) != 0 ||
        lstat(PRIVATE_PATHS[index].path, &status) != 0 || status.st_uid != 0 ||
        status.st_gid != 0 || (status.st_mode & 07777) != PRIVATE_PATHS[index].mode ||
        (is_file
             ? (!S_ISREG(status.st_mode) || status.st_nlink != 1 ||
                status.st_size < 1 || status.st_size > 256 * 1024)
             : (is_socket ? (!S_ISSOCK(status.st_mode) || status.st_nlink != 1)
                          : (!S_ISDIR(status.st_mode) || status.st_nlink < 2)))) {
      return false;
    }
    private_paths[index].path = PRIVATE_PATHS[index].path;
    private_paths[index].type = PRIVATE_PATHS[index].type;
    private_paths[index].uid = status.st_uid;
    private_paths[index].gid = status.st_gid;
    private_paths[index].mode = status.st_mode & 07777;
    private_paths[index].nlink = status.st_nlink;
  }
  for (index = 0; index < sizeof(EXECUTABLES) / sizeof(EXECUTABLES[0]); index++) {
    char resolved[4096];
    if (realpath(EXECUTABLES[index].path, resolved) == NULL ||
        strcmp(resolved, EXECUTABLES[index].path) != 0 ||
        lstat(EXECUTABLES[index].path, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_nlink != 1 || status.st_uid != 0 || status.st_gid != 0 ||
        (status.st_mode & 07777) != EXECUTABLES[index].mode || status.st_size < 1 ||
        status.st_size > 256 * 1024 * 1024) {
      return false;
    }
    executables[index].path = EXECUTABLES[index].path;
    executables[index].type = "file";
    executables[index].uid = status.st_uid;
    executables[index].gid = status.st_gid;
    executables[index].mode = status.st_mode & 07777;
    executables[index].nlink = status.st_nlink;
  }
  return true;
}

static bool clear_capability_sets(void) {
  struct __user_cap_header_struct header;
  struct __user_cap_data_struct data[2];
  memset(&header, 0, sizeof(header));
  memset(data, 0, sizeof(data));
  header.version = _LINUX_CAPABILITY_VERSION_3;
  header.pid = 0;
  if (syscall(SYS_capset, &header, data) != 0) {
    return false;
  }
#ifdef PR_CAP_AMBIENT
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 &&
      errno != EINVAL) {
    return false;
  }
#endif
  return true;
}

static bool denied_open(const char *path, int flags) {
  int descriptor;
  errno = 0;
  descriptor = open(path, flags | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor >= 0) {
    (void)close(descriptor);
    return false;
  }
  return errno == EACCES || errno == EPERM;
}

static bool denied_create(const char *directory, const char *name) {
  char path[512];
  int descriptor;
  if (snprintf(path, sizeof(path), "%s/%s", directory, name) < 1) {
    return false;
  }
  errno = 0;
  descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
  if (descriptor >= 0) {
    (void)close(descriptor);
    (void)unlink(path);
    return false;
  }
  return errno == EACCES || errno == EPERM;
}

static bool denied_signal(pid_t target) {
  errno = 0;
  return kill(target, 0) != 0 && errno == EPERM;
}

static void erase_inherited_environment(void) {
  char **entry;
  for (entry = environ; entry != NULL && *entry != NULL; entry++) {
    volatile char *byte = (volatile char *)*entry;
    size_t remaining = strlen(*entry);
    while (remaining > 0) {
      *byte = '\0';
      byte++;
      remaining--;
    }
  }
  (void)clearenv();
}

static bool process_environment_is_safe(pid_t pid, bool daemon) {
  static const char fixed_id[] = "DAYTONA_SANDBOX_ID=terminalx-sandbox";
  static const char id_prefix[] = "DAYTONA_SANDBOX_ID=";
  static const char snapshot_prefix[] = "DAYTONA_SANDBOX_SNAPSHOT=";
  static const char user_prefix[] = "DAYTONA_SANDBOX_USER=";
  char path[64];
  char bytes[MAX_ENVIRONMENT_BYTES + 1];
  size_t length = 0;
  size_t offset = 0;
  unsigned int fixed_id_count = 0;
  int descriptor;
  if (snprintf(path, sizeof(path), "/proc/%ld/environ", (long)pid) < 1) {
    return false;
  }
  descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    return errno == EACCES || errno == EPERM || errno == ENOENT;
  }
  while (length < sizeof(bytes)) {
    ssize_t count = read(descriptor, bytes + length, sizeof(bytes) - length);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      (void)close(descriptor);
      memset(bytes, 0, sizeof(bytes));
      return false;
    }
    if (count == 0) {
      break;
    }
    length += (size_t)count;
  }
  (void)close(descriptor);
  if (length > MAX_ENVIRONMENT_BYTES) {
    memset(bytes, 0, sizeof(bytes));
    return false;
  }
  while (offset < length) {
    size_t entry_length = 0;
    while (offset + entry_length < length && bytes[offset + entry_length] != '\0') {
      entry_length++;
    }
    if (entry_length >= sizeof(snapshot_prefix) - 1 &&
        memcmp(bytes + offset, snapshot_prefix, sizeof(snapshot_prefix) - 1) == 0) {
      memset(bytes, 0, sizeof(bytes));
      return false;
    }
    if (entry_length >= sizeof(user_prefix) - 1 &&
        memcmp(bytes + offset, user_prefix, sizeof(user_prefix) - 1) == 0) {
      memset(bytes, 0, sizeof(bytes));
      return false;
    }
    if (entry_length >= sizeof(id_prefix) - 1 &&
        memcmp(bytes + offset, id_prefix, sizeof(id_prefix) - 1) == 0) {
      if (!daemon || entry_length != sizeof(fixed_id) - 1 ||
          memcmp(bytes + offset, fixed_id, sizeof(fixed_id) - 1) != 0) {
        memset(bytes, 0, sizeof(bytes));
        return false;
      }
      fixed_id_count++;
    }
    offset += entry_length + 1;
  }
  memset(bytes, 0, sizeof(bytes));
  return daemon ? fixed_id_count == 1 : fixed_id_count == 0;
}

static bool all_agent_environments_safe(pid_t daemon_pid) {
  DIR *directory = opendir("/proc");
  struct dirent *entry;
  size_t inspected = 0;
  if (directory == NULL) {
    return false;
  }
  for (;;) {
    char *end = NULL;
    long parsed;
    struct process_state state;
    errno = 0;
    entry = readdir(directory);
    if (entry == NULL) {
      bool success = errno == 0;
      (void)closedir(directory);
      return success;
    }
    if (entry->d_name[0] < '1' || entry->d_name[0] > '9') {
      continue;
    }
    errno = 0;
    parsed = strtol(entry->d_name, &end, 10);
    if (errno != 0 || end == entry->d_name || *end != '\0' || parsed < 1 ||
        parsed > INT32_MAX || ++inspected > MAX_PROCESSES) {
      (void)closedir(directory);
      return false;
    }
    if (!read_process_state((pid_t)parsed, &state)) {
      if (errno == ENOENT) {
        errno = 0;
        continue;
      }
      (void)closedir(directory);
      return false;
    }
    if (any_process_uid(&state, TERMINALX_UID) &&
        !process_environment_is_safe(state.pid, state.pid == daemon_pid)) {
      (void)closedir(directory);
      return false;
    }
  }
}

static bool run_denial_child(pid_t init_pid, pid_t supervisor_pid,
                             pid_t daemon_pid, struct denial_result *output) {
  int descriptors[2];
  pid_t child;
  ssize_t length;
  int status;
  if (pipe2(descriptors, O_CLOEXEC) != 0) {
    return false;
  }
  child = fork();
  if (child < 0) {
    (void)close(descriptors[0]);
    (void)close(descriptors[1]);
    return false;
  }
  if (child == 0) {
    struct denial_result result;
    struct process_state state;
    char runtime_name[96];
    char state_name[96];
    size_t index;
    bool read_denied = true;
    bool write_denied = true;
    (void)close(descriptors[0]);
    memset(&result, 0, sizeof(result));
    erase_inherited_environment();
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || setgroups(0, NULL) != 0 ||
        setresgid(TERMINALX_GID, TERMINALX_GID, TERMINALX_GID) != 0 ||
        setresuid(TERMINALX_UID, TERMINALX_UID, TERMINALX_UID) != 0 ||
        !clear_capability_sets() || !read_process_state(getpid(), &state) ||
        !all_process_ids(&state, TERMINALX_UID, TERMINALX_GID) ||
        state.cap_inheritable != 0 || state.cap_permitted != 0 ||
        state.cap_effective != 0 || state.cap_bounding != EXPECTED_AGENT_BOUNDING_SET ||
        state.cap_ambient != 0 || state.no_new_privileges != 1 ||
        !state.supplementary_groups_empty) {
      _exit(1);
    }
    for (index = 0; index < sizeof(PRIVATE_KEYS) / sizeof(PRIVATE_KEYS[0]); index++) {
      read_denied = read_denied && denied_open(PRIVATE_KEYS[index], O_RDONLY);
      write_denied = write_denied && denied_open(PRIVATE_KEYS[index], O_WRONLY);
    }
    if (snprintf(runtime_name, sizeof(runtime_name), ".agent-probe-%ld",
                 (long)getpid()) < 1 ||
        snprintf(state_name, sizeof(state_name), ".agent-probe-%ld", (long)getpid()) <
            1) {
      _exit(1);
    }
    result.private_key_read_denied = read_denied;
    result.private_key_write_denied = write_denied;
    result.root_runtime_write_denied = denied_create(RUNTIME_ROOT, runtime_name);
    result.root_state_write_denied =
        denied_create("/var/lib/terminalx-supervisor", state_name);
    result.signal_init_denied = denied_signal(init_pid);
    result.signal_supervisor_denied = denied_signal(supervisor_pid);
    result.agent_environment_safe = all_agent_environments_safe(daemon_pid);
    length = write(descriptors[1], &result, sizeof(result));
    _exit(length == (ssize_t)sizeof(result) ? 0 : 1);
  }
  (void)close(descriptors[1]);
  memset(output, 0, sizeof(*output));
  length = read(descriptors[0], output, sizeof(*output));
  (void)close(descriptors[0]);
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0 || length != (ssize_t)sizeof(*output)) {
    return false;
  }
  return output->private_key_read_denied == 1 &&
         output->private_key_write_denied == 1 &&
         output->root_runtime_write_denied == 1 &&
         output->root_state_write_denied == 1 &&
         output->signal_init_denied == 1 &&
         output->signal_supervisor_denied == 1 &&
         output->agent_environment_safe == 1;
}

static void append(struct output_buffer *output, const char *format, ...) {
  va_list arguments;
  int written;
  if (output->failed || output->length >= sizeof(output->bytes)) {
    output->failed = true;
    return;
  }
  va_start(arguments, format);
  written = vsnprintf(output->bytes + output->length,
                      sizeof(output->bytes) - output->length, format, arguments);
  va_end(arguments);
  if (written < 0 || (size_t)written >= sizeof(output->bytes) - output->length) {
    output->failed = true;
    return;
  }
  output->length += (size_t)written;
}

static void append_process(struct output_buffer *output,
                           const struct process_state *process) {
  append(output,
         "{\"capAmbient\":\"%016llx\",\"capBounding\":\"%016llx\","
         "\"capEffective\":\"%016llx\",\"capInheritable\":\"%016llx\","
         "\"capPermitted\":\"%016llx\",\"effectiveGid\":%u,"
         "\"effectiveUid\":%u,\"filesystemGid\":%u,\"filesystemUid\":%u,"
         "\"noNewPrivileges\":%s,\"pid\":%ld,\"realGid\":%u,"
         "\"realUid\":%u,\"savedGid\":%u,\"savedUid\":%u}",
         (unsigned long long)process->cap_ambient,
         (unsigned long long)process->cap_bounding,
         (unsigned long long)process->cap_effective,
         (unsigned long long)process->cap_inheritable,
         (unsigned long long)process->cap_permitted, (unsigned int)process->gid[1],
         (unsigned int)process->uid[1], (unsigned int)process->gid[3],
         (unsigned int)process->uid[3],
         process->no_new_privileges == 1 ? "true" : "false", (long)process->pid,
         (unsigned int)process->gid[0], (unsigned int)process->uid[0],
         (unsigned int)process->gid[2], (unsigned int)process->uid[2]);
}

static void append_agent(struct output_buffer *output,
                         const struct agent_aggregate *agent) {
  append(output,
         "{\"capAmbient\":\"%016llx\",\"capBounding\":\"%016llx\","
         "\"capEffective\":\"%016llx\",\"capInheritable\":\"%016llx\","
         "\"capPermitted\":\"%016llx\",\"effectiveGid\":10001,"
         "\"effectiveUid\":10001,\"filesystemGid\":10001,"
         "\"filesystemUid\":10001,\"noNewPrivileges\":true,"
         "\"processCount\":%zu,\"realGid\":10001,\"realUid\":10001,"
         "\"savedGid\":10001,\"savedUid\":10001}",
         (unsigned long long)agent->cap_ambient,
         (unsigned long long)agent->cap_bounding,
         (unsigned long long)agent->cap_effective,
         (unsigned long long)agent->cap_inheritable,
         (unsigned long long)agent->cap_permitted, agent->process_count);
}

static bool emit_canonical_json(const struct agent_aggregate *agent,
                                const struct process_state *daemon,
                                const struct denial_result *denials,
                                const struct measured_path *executables,
                                const struct process_state *init,
                                const struct measured_path *private_paths,
                                const struct process_state *supervisor) {
  struct output_buffer output;
  size_t index;
  size_t output_length;
  ssize_t written;
  memset(&output, 0, sizeof(output));
  append(&output, "{\"agent\":");
  append_agent(&output, agent);
  append(&output, ",\"daemon\":");
  append_process(&output, daemon);
  append(&output,
         ",\"denials\":{\"agentPrivateKeyReadDenied\":true,"
         "\"agentPrivateKeyWriteDenied\":true,"
         "\"agentRootRuntimeWriteDenied\":true,"
         "\"agentRootStateWriteDenied\":true,\"agentSignalInitDenied\":true,"
         "\"agentSignalSupervisorDenied\":true},\"executables\":[");
  (void)denials;
  for (index = 0; index < sizeof(EXECUTABLES) / sizeof(EXECUTABLES[0]); index++) {
    append(&output,
           "%s{\"gid\":%u,\"mode\":%u,\"nlink\":%lu,\"path\":\"%s\","
           "\"regular\":true,\"uid\":%u}",
           index == 0 ? "" : ",", (unsigned int)executables[index].gid,
           (unsigned int)executables[index].mode,
           (unsigned long)executables[index].nlink, executables[index].path,
           (unsigned int)executables[index].uid);
  }
  append(&output, "],\"init\":");
  append_process(&output, init);
  append(&output,
         ",\"kind\":\"terminalx.daytona-isolation-probe\","
         "\"rootPrivatePaths\":[");
  for (index = 0; index < sizeof(PRIVATE_PATHS) / sizeof(PRIVATE_PATHS[0]); index++) {
    append(&output,
           "%s{\"gid\":%u,\"mode\":%u,\"nlink\":%lu,\"path\":\"%s\","
           "\"type\":\"%s\",\"uid\":%u}",
           index == 0 ? "" : ",", (unsigned int)private_paths[index].gid,
           (unsigned int)private_paths[index].mode,
           (unsigned long)private_paths[index].nlink, private_paths[index].path,
           private_paths[index].type, (unsigned int)private_paths[index].uid);
  }
  append(&output, "],\"supervisor\":");
  append_process(&output, supervisor);
  append(&output, ",\"version\":1}");
  if (output.failed || output.length < 2 || output.length > 4096) {
    memset(&output, 0, sizeof(output));
    return false;
  }
  output_length = output.length;
  written = write(STDOUT_FILENO, output.bytes, output_length);
  memset(&output, 0, sizeof(output));
  return written == (ssize_t)output_length;
}

int main(int argc, char **argv) {
  struct process_state init;
  struct process_state daemon;
  struct process_state supervisor;
  struct agent_aggregate agent;
  struct denial_result denials;
  struct measured_path private_paths[sizeof(PRIVATE_PATHS) / sizeof(PRIVATE_PATHS[0])];
  struct measured_path executables[sizeof(EXECUTABLES) / sizeof(EXECUTABLES[0])];
  static const char failure[] = "TerminalX isolation probe failed closed\n";
  (void)argv;
  (void)umask(0077);
  if (argc != 1 || geteuid() != 0 || getegid() != 0 ||
      !validate_fixed_environment() || !validate_fixed_hostname() ||
      !scan_processes(&init, &daemon, &supervisor, &agent) ||
      !measure_fixed_paths(private_paths, executables) ||
      !run_denial_child(init.pid, supervisor.pid, daemon.pid, &denials) ||
      !emit_canonical_json(&agent, &daemon, &denials, executables, &init,
                           private_paths, &supervisor)) {
    ssize_t ignored = write(STDERR_FILENO, failure, sizeof(failure) - 1);
    (void)ignored;
    return 74;
  }
  return 0;
}
