#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define TERMINALX_UID ((uid_t)10001)
#define TERMINALX_GID ((gid_t)10001)
#define ASSIGNMENT_WAIT_SECONDS 300
#define SUPERVISOR_SOCKET_WAIT_SECONDS 15
#define SHUTDOWN_GRACE_SECONDS 10
#define KILL_REAP_SECONDS 2
#define EXPECTED_ROOT_CAPABILITIES UINT64_C(0x00000000000000e1)

static const char *const INIT_PATH = "/usr/local/bin/terminalx-sandbox-init";
static const char *const DAYTONA_PATH = "/usr/local/bin/daytona";
static const char *const NODE_PATH = "/usr/local/bin/node";
static const char *const LIBEXEC_ROOT = "/usr/local/libexec/terminalx";
static const char *const SUPERVISOR_PATH =
    "/usr/local/libexec/terminalx/terminalx-daytona-supervisor";
static const char *const RELAY_PATH =
    "/usr/local/libexec/terminalx/terminalx-supervisor-relay";
static const char *const BOOTSTRAP_PATH =
    "/usr/local/libexec/terminalx/terminalx-assignment-bootstrap";
static const char *const PEERCRED_PATH =
    "/usr/local/libexec/terminalx/terminalx-peercred";
static const char *const EFFECT_PATH =
    "/usr/local/libexec/terminalx/terminalx-effect-enforcer";
static const char *const DEPLOYMENT_BINDING_INSTALL_PATH =
    "/usr/local/libexec/terminalx/terminalx-deployment-binding-install";
static const char *const ISOLATION_PROBE_PATH =
    "/usr/local/libexec/terminalx/terminalx-isolation-probe";
static const char *const TRUST_ROOT = "/etc/terminalx";
static const char *const AUTHORITY_PIN =
    "/etc/terminalx/bootstrap-authority-pin.json";
static const char *const IMAGE_PINS = "/etc/terminalx/sandbox-trust-pins.json";
static const char *const RUNTIME_ARTIFACT_MANIFEST =
    "/usr/share/terminalx/daytona-runtime-artifact-manifest.json";
static const char *const RUNTIME_ROOT = "/run/terminalx-root";
static const char *const PRIVATE_RUNTIME_ROOT = "/run/terminalx-private";
static const char *const DAYTONA_SOCKET =
    "/run/terminalx-private/daytona-daemon.sock";
static const char *const LIVE_ROOT = "/run/terminalx-root/live";
static const char *const ASSIGNMENT_ROOT = "/run/terminalx-root/assignment";
static const char *const ASSIGNMENT_MARKER =
    "/run/terminalx-root/assignment.installed.json";
static const char *const BOOTSTRAP_CONFIG =
    "/run/terminalx-root/assignment/bootstrap.json";
static const char *const SUPERVISOR_SOCKET =
    "/run/terminalx-root/supervisor.sock";
static const char *const STATE_ROOT = "/var/lib/terminalx-supervisor";
static const char *const TERMINALX_HOME = "/home/terminalx";
static const char *const SANDBOX_HOSTNAME = "terminalx-sandbox";

extern char **environ;

struct sandbox_environment {
  const char *sandbox_id_entry;
  const char *sandbox_snapshot_entry;
  const char *sandbox_user_entry;
  const char *sandbox_id;
  const char *sandbox_snapshot;
};

static volatile sig_atomic_t shutdown_signal = 0;

static void remember_signal(int signal_number) {
  if (shutdown_signal == 0) {
    shutdown_signal = signal_number;
  }
}

static bool lowercase_hex(char value) {
  return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
}

static bool valid_uuid_v4(const char *value) {
  size_t index;
  if (value == NULL || strlen(value) != 36 || value[8] != '-' ||
      value[13] != '-' || value[18] != '-' || value[23] != '-' ||
      value[14] != '4' || strchr("89ab", value[19]) == NULL) {
    return false;
  }
  for (index = 0; index < 36; index++) {
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      continue;
    }
    if (!lowercase_hex(value[index])) {
      return false;
    }
  }
  return true;
}

static bool valid_snapshot_reference(const char *value) {
  size_t index;
  size_t length;
  if (value == NULL) {
    return false;
  }
  length = strlen(value);
  if (length < 1 || length > 300) {
    return false;
  }
  for (index = 0; index < length; index++) {
    unsigned char byte = (unsigned char)value[index];
    if (byte <= 0x20 || byte == 0x7f) {
      return false;
    }
  }
  return true;
}

static bool capture_environment(struct sandbox_environment *output) {
  size_t count = 0;
  char **entry;
  memset(output, 0, sizeof(*output));
  for (entry = environ; entry != NULL && *entry != NULL; entry++) {
    count++;
    if (strncmp(*entry, "DAYTONA_SANDBOX_ID=", 19) == 0 &&
        output->sandbox_id_entry == NULL) {
      output->sandbox_id_entry = *entry;
      output->sandbox_id = *entry + 19;
    } else if (strncmp(*entry, "DAYTONA_SANDBOX_SNAPSHOT=", 25) == 0 &&
               output->sandbox_snapshot_entry == NULL) {
      output->sandbox_snapshot_entry = *entry;
      output->sandbox_snapshot = *entry + 25;
    } else if (strcmp(*entry, "DAYTONA_SANDBOX_USER=terminalx") == 0 &&
               output->sandbox_user_entry == NULL) {
      output->sandbox_user_entry = *entry;
    } else {
      return false;
    }
  }
  return count == 3 && output->sandbox_id_entry != NULL &&
         output->sandbox_snapshot_entry != NULL &&
         output->sandbox_user_entry != NULL && valid_uuid_v4(output->sandbox_id) &&
         valid_snapshot_reference(output->sandbox_snapshot);
}

static bool hostname_matches(void) {
  char hostname[257];
  memset(hostname, 0, sizeof(hostname));
  if (gethostname(hostname, sizeof(hostname) - 1) != 0) {
    return false;
  }
  hostname[sizeof(hostname) - 1] = '\0';
  return strcmp(hostname, SANDBOX_HOSTNAME) == 0;
}

static bool protected_directory(const char *path, uid_t owner, gid_t group,
                                mode_t mode) {
  struct stat status;
  char resolved[4096];
  return realpath(path, resolved) != NULL && strcmp(resolved, path) == 0 &&
         lstat(path, &status) == 0 && S_ISDIR(status.st_mode) &&
         status.st_uid == owner && status.st_gid == group &&
         (status.st_mode & 07777) == mode;
}

static bool protected_regular_file(const char *path, mode_t mode,
                                   off_t maximum_size) {
  struct stat status;
  char resolved[4096];
  return realpath(path, resolved) != NULL && strcmp(resolved, path) == 0 &&
         lstat(path, &status) == 0 && S_ISREG(status.st_mode) &&
         status.st_nlink == 1 && status.st_uid == 0 && status.st_gid == 0 &&
         (status.st_mode & 07777) == mode && status.st_size > 0 &&
         status.st_size <= maximum_size;
}

static bool protected_runtime_file_or_absent(const char *path, mode_t mode,
                                             off_t maximum_size,
                                             bool *is_present) {
  struct stat status;
  if (lstat(path, &status) != 0) {
    if (errno == ENOENT) {
      *is_present = false;
      return true;
    }
    return false;
  }
  *is_present = true;
  return S_ISREG(status.st_mode) && status.st_nlink == 1 &&
         status.st_uid == 0 && status.st_gid == 0 &&
         (status.st_mode & 07777) == mode && status.st_size > 0 &&
         status.st_size <= maximum_size;
}

static bool protected_socket_or_absent(const char *path, bool *is_present) {
  struct stat status;
  if (lstat(path, &status) != 0) {
    if (errno == ENOENT) {
      *is_present = false;
      return true;
    }
    return false;
  }
  *is_present = true;
  return S_ISSOCK(status.st_mode) && status.st_uid == 0 && status.st_gid == 0 &&
         (status.st_mode & 07777) == 0600;
}

static bool validate_image_boundary(void) {
  struct passwd *account = getpwnam("terminalx");
  return account != NULL && account->pw_uid == TERMINALX_UID &&
         account->pw_gid == TERMINALX_GID && account->pw_dir != NULL &&
         strcmp(account->pw_dir, TERMINALX_HOME) == 0 &&
         protected_directory(TERMINALX_HOME, TERMINALX_UID, TERMINALX_GID, 0700) &&
         protected_directory(TRUST_ROOT, 0, 0, 0500) &&
         protected_directory(LIBEXEC_ROOT, 0, 0, 0500) &&
         protected_directory(PRIVATE_RUNTIME_ROOT, 0, 0, 0700) &&
         protected_directory(RUNTIME_ROOT, 0, 0, 0700) &&
         protected_directory(LIVE_ROOT, 0, 0, 0700) &&
         protected_directory(STATE_ROOT, 0, 0, 0700) &&
         protected_regular_file(INIT_PATH, 0555, 16 * 1024 * 1024) &&
         protected_regular_file(DAYTONA_PATH, 0555, 256 * 1024 * 1024) &&
         protected_regular_file(NODE_PATH, 0555, 256 * 1024 * 1024) &&
         protected_regular_file(SUPERVISOR_PATH, 0555, 128 * 1024 * 1024) &&
         protected_regular_file(RELAY_PATH, 0555, 128 * 1024 * 1024) &&
         protected_regular_file(BOOTSTRAP_PATH, 0555, 128 * 1024 * 1024) &&
         protected_regular_file(PEERCRED_PATH, 0500, 16 * 1024 * 1024) &&
         protected_regular_file(EFFECT_PATH, 0500, 128 * 1024 * 1024) &&
         protected_regular_file(DEPLOYMENT_BINDING_INSTALL_PATH, 0555,
                                16 * 1024 * 1024) &&
         protected_regular_file(ISOLATION_PROBE_PATH, 0555,
                                16 * 1024 * 1024) &&
         protected_regular_file(AUTHORITY_PIN, 0600, 64 * 1024) &&
         protected_regular_file(IMAGE_PINS, 0600, 256 * 1024) &&
         protected_regular_file(RUNTIME_ARTIFACT_MANIFEST, 0444, 64 * 1024);
}

static void reset_process_signals(void) {
  struct sigaction action;
  sigset_t empty;
  size_t index;
  static const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGCHLD};
  memset(&action, 0, sizeof(action));
  action.sa_handler = SIG_DFL;
  sigemptyset(&action.sa_mask);
  for (index = 0; index < sizeof(signals) / sizeof(signals[0]); index++) {
    (void)sigaction(signals[index], &action, NULL);
  }
  sigemptyset(&empty);
  (void)sigprocmask(SIG_SETMASK, &empty, NULL);
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

static bool confine_root_identity_and_capabilities(void) {
  struct __user_cap_header_struct header;
  struct __user_cap_data_struct data[2];
  uid_t real_uid, effective_uid, saved_uid;
  gid_t real_gid, effective_gid, saved_gid;
  unsigned int capability;

  if (setgroups(0, NULL) != 0 || setresgid(0, 0, 0) != 0 ||
      setresuid(0, 0, 0) != 0 ||
      getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
      getresgid(&real_gid, &effective_gid, &saved_gid) != 0 || real_uid != 0 ||
      effective_uid != 0 || saved_uid != 0 || real_gid != 0 ||
      effective_gid != 0 || saved_gid != 0) {
    return false;
  }

  for (capability = 0; capability < 64U; capability++) {
    uint64_t bit = UINT64_C(1) << capability;
    int bounded = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);
    if (bounded < 0) {
      if (errno == EINVAL) {
        continue;
      }
      return false;
    }
    if ((EXPECTED_ROOT_CAPABILITIES & bit) != 0) {
      if (bounded != 1) {
        return false;
      }
    } else if (bounded != 0 &&
               prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0) {
      return false;
    }
  }

  memset(&header, 0, sizeof(header));
  memset(data, 0, sizeof(data));
  header.version = _LINUX_CAPABILITY_VERSION_3;
  header.pid = 0;
  data[0].permitted = (__u32)(EXPECTED_ROOT_CAPABILITIES & UINT32_MAX);
  data[0].effective = data[0].permitted;
  data[1].permitted = (__u32)(EXPECTED_ROOT_CAPABILITIES >> 32U);
  data[1].effective = data[1].permitted;
  if (syscall(SYS_capset, &header, data) != 0) {
    return false;
  }
#ifdef PR_CAP_AMBIENT
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) {
    return false;
  }
#endif

  memset(data, 0, sizeof(data));
  if (syscall(SYS_capget, &header, data) != 0 || data[0].inheritable != 0 ||
      data[1].inheritable != 0 ||
      data[0].permitted != (__u32)(EXPECTED_ROOT_CAPABILITIES & UINT32_MAX) ||
      data[1].permitted != (__u32)(EXPECTED_ROOT_CAPABILITIES >> 32U) ||
      data[0].effective != (__u32)(EXPECTED_ROOT_CAPABILITIES & UINT32_MAX) ||
      data[1].effective != (__u32)(EXPECTED_ROOT_CAPABILITIES >> 32U)) {
    return false;
  }
  for (capability = 0; capability < 64U; capability++) {
    uint64_t bit = UINT64_C(1) << capability;
    int bounded = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);
    if (bounded < 0) {
      if (errno == EINVAL) {
        continue;
      }
      return false;
    }
    if (((EXPECTED_ROOT_CAPABILITIES & bit) != 0) != (bounded == 1)) {
      return false;
    }
  }
  return true;
}

static bool empty_agent_capability_sets(void) {
  FILE *status = fopen("/proc/self/status", "re");
  char line[256];
  unsigned int found = 0;
  if (status == NULL) {
    return false;
  }
  while (fgets(line, sizeof(line), status) != NULL) {
    static const char *const names[] = {"CapInh:\t", "CapPrm:\t", "CapEff:\t",
                                        "CapAmb:\t"};
    size_t index;
    for (index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
      size_t length = strlen(names[index]);
      if (strncmp(line, names[index], length) == 0) {
        char *end = NULL;
        unsigned long long value;
        errno = 0;
        value = strtoull(line + length, &end, 16);
        if (errno != 0 || end == line + length || value != 0) {
          (void)fclose(status);
          return false;
        }
        found |= 1U << index;
      }
    }
  }
  return fclose(status) == 0 && found == 0x0f;
}

static void close_inherited_descriptors_from(unsigned int first) {
#ifdef SYS_close_range
  if (syscall(SYS_close_range, first, ~0U, 0U) == 0) {
    return;
  }
#endif
  {
    long maximum = sysconf(_SC_OPEN_MAX);
    int descriptor;
    if (maximum < 0 || maximum > 65536) {
      maximum = 65536;
    }
    for (descriptor = (int)first; descriptor < maximum; descriptor++) {
      (void)close(descriptor);
    }
  }
}

static bool redirect_stdin(void) {
  int descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return false;
  }
  if (descriptor != STDIN_FILENO && dup2(descriptor, STDIN_FILENO) < 0) {
    (void)close(descriptor);
    return false;
  }
  if (descriptor != STDIN_FILENO) {
    (void)close(descriptor);
  }
  return true;
}

static int create_daytona_listener(void) {
  struct sockaddr_un address;
  struct stat status;
  int descriptor = -1;
  size_t socket_path_length = strlen(DAYTONA_SOCKET);
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  if (socket_path_length >= sizeof(address.sun_path)) {
    return -1;
  }
  memcpy(address.sun_path, DAYTONA_SOCKET, socket_path_length + 1);
  if (lstat(DAYTONA_SOCKET, &status) == 0 || errno != ENOENT) {
    return -1;
  }
  descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0) {
    return -1;
  }
  if (descriptor < 3) {
    int replacement = fcntl(descriptor, F_DUPFD_CLOEXEC, 3);
    (void)close(descriptor);
    descriptor = replacement;
    if (descriptor < 3) {
      return -1;
    }
  }
  if (bind(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) {
    (void)close(descriptor);
    return -1;
  }
  if (chmod(DAYTONA_SOCKET, 0600) != 0 ||
      lstat(DAYTONA_SOCKET, &status) != 0 || !S_ISSOCK(status.st_mode) ||
      status.st_nlink != 1 || status.st_uid != 0 || status.st_gid != 0 ||
      (status.st_mode & 07777) != 0600 || listen(descriptor, 128) != 0) {
    (void)close(descriptor);
    if (lstat(DAYTONA_SOCKET, &status) == 0 && S_ISSOCK(status.st_mode) &&
        status.st_uid == 0 && status.st_gid == 0) {
      (void)unlink(DAYTONA_SOCKET);
    }
    return -1;
  }
  return descriptor;
}

static bool remove_daytona_listener(void) {
  struct stat status;
  if (lstat(DAYTONA_SOCKET, &status) != 0) {
    return errno == ENOENT;
  }
  if (!S_ISSOCK(status.st_mode) || status.st_nlink != 1 || status.st_uid != 0 ||
      status.st_gid != 0 ||
      (status.st_mode & 07777) != 0600) {
    return false;
  }
  return unlink(DAYTONA_SOCKET) == 0;
}

static pid_t spawn_daytona(int listener) {
  pid_t child = fork();
  if (child != 0) {
    if (child > 0) {
      (void)setpgid(child, child);
    }
    return child;
  }
  {
    char *const arguments[] = {
        (char *)DAYTONA_PATH, "--terminalx-toolbox-listener-fd=3", NULL};
    char *const child_environment[] = {
        "DAYTONA_SANDBOX_ID=terminalx-sandbox",
        "HOME=/home/terminalx",
        "USER=terminalx",
        "LOGNAME=terminalx",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "DAYTONA_DAEMON_LOG_FILE_PATH=/home/terminalx/.daytona/daytona-daemon.log",
        NULL,
    };
    int descriptor_flags;
    reset_process_signals();
    (void)setpgid(0, 0);
    (void)umask(0077);
    descriptor_flags = listener == 3 ? fcntl(listener, F_GETFD) : 0;
    if ((listener == 3
             ? (descriptor_flags < 0 ||
                fcntl(listener, F_SETFD, descriptor_flags & ~FD_CLOEXEC) != 0)
             : dup3(listener, 3, 0) != 3) ||
        !redirect_stdin() || chdir(TERMINALX_HOME) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        setgroups(0, NULL) != 0 || setresgid(TERMINALX_GID, TERMINALX_GID,
                                           TERMINALX_GID) != 0 ||
        setresuid(TERMINALX_UID, TERMINALX_UID, TERMINALX_UID) != 0 ||
        !clear_capability_sets() || !empty_agent_capability_sets()) {
      _exit(126);
    }
    close_inherited_descriptors_from(4U);
    execve(DAYTONA_PATH, arguments, child_environment);
    _exit(126);
  }
}

static pid_t spawn_supervisor(const struct sandbox_environment *environment) {
  pid_t child = fork();
  if (child != 0) {
    if (child > 0) {
      (void)setpgid(child, child);
    }
    return child;
  }
  {
    char *const arguments[] = {(char *)SUPERVISOR_PATH, (char *)RUNTIME_ROOT,
                               (char *)BOOTSTRAP_CONFIG, NULL};
    char *const child_environment[] = {
        (char *)environment->sandbox_id_entry,
        (char *)environment->sandbox_snapshot_entry,
        (char *)environment->sandbox_user_entry,
        "HOME=/root",
        "USER=root",
        "LOGNAME=root",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "NODE_ENV=production",
        NULL,
    };
    reset_process_signals();
    (void)setpgid(0, 0);
    (void)umask(0077);
    if (!redirect_stdin() || chdir("/") != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(126);
    }
    close_inherited_descriptors_from(3U);
    execve(SUPERVISOR_PATH, arguments, child_environment);
    _exit(126);
  }
}

static int64_t monotonic_seconds(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    return -1;
  }
  return (int64_t)now.tv_sec;
}

static void short_pause(void) {
  struct timespec duration = {.tv_sec = 0, .tv_nsec = 100 * 1000 * 1000};
  while (nanosleep(&duration, &duration) != 0 && errno == EINTR &&
         shutdown_signal == 0) {
  }
}

static bool child_is_running(pid_t child) {
  siginfo_t information;
  memset(&information, 0, sizeof(information));
  return waitid(P_PID, (id_t)child, &information,
                WEXITED | WNOHANG | WNOWAIT) == 0 && information.si_pid == 0;
}

static bool wait_for_assignment(pid_t daemon) {
  int64_t started = monotonic_seconds();
  if (started < 0) {
    return false;
  }
  while (shutdown_signal == 0 && monotonic_seconds() - started < ASSIGNMENT_WAIT_SECONDS) {
    bool marker_present = false;
    if (!child_is_running(daemon) ||
        !protected_runtime_file_or_absent(ASSIGNMENT_MARKER, 0600,
                                          256 * 1024, &marker_present)) {
      return false;
    }
    if (marker_present) {
      return protected_directory(ASSIGNMENT_ROOT, 0, 0, 0700) &&
             protected_regular_file(BOOTSTRAP_CONFIG, 0600, 1024 * 1024);
    }
    short_pause();
  }
  return false;
}

static bool wait_for_supervisor_socket(pid_t daemon, pid_t supervisor) {
  int64_t started = monotonic_seconds();
  if (started < 0) {
    return false;
  }
  while (shutdown_signal == 0 &&
         monotonic_seconds() - started < SUPERVISOR_SOCKET_WAIT_SECONDS) {
    bool socket_present = false;
    if (!child_is_running(daemon) || !child_is_running(supervisor) ||
        !protected_socket_or_absent(SUPERVISOR_SOCKET, &socket_present)) {
      return false;
    }
    if (socket_present) {
      return true;
    }
    short_pause();
  }
  return false;
}

static void signal_process_group(pid_t child, int signal_number) {
  if (child <= 0) {
    return;
  }
  (void)kill(-child, signal_number);
  (void)kill(child, signal_number);
}

static void reap_available(void) {
  int status;
  while (waitpid(-1, &status, WNOHANG) > 0) {
  }
}

static void stop_children(pid_t daemon, pid_t supervisor) {
  int64_t started;
  signal_process_group(supervisor, SIGTERM);
  signal_process_group(daemon, SIGTERM);
  started = monotonic_seconds();
  while (started >= 0 && monotonic_seconds() - started < SHUTDOWN_GRACE_SECONDS) {
    bool daemon_alive = daemon > 0 && kill(daemon, 0) == 0;
    bool supervisor_alive = supervisor > 0 && kill(supervisor, 0) == 0;
    reap_available();
    if (!daemon_alive && !supervisor_alive) {
      return;
    }
    short_pause();
  }
  signal_process_group(supervisor, SIGKILL);
  signal_process_group(daemon, SIGKILL);
  started = monotonic_seconds();
  while (started >= 0 && monotonic_seconds() - started < KILL_REAP_SECONDS) {
    reap_available();
    short_pause();
  }
  reap_available();
}

static int supervise(pid_t daemon, pid_t supervisor) {
  while (shutdown_signal == 0) {
    int status;
    pid_t exited = waitpid(-1, &status, WNOHANG);
    if (exited == daemon || exited == supervisor) {
      stop_children(daemon, supervisor);
      return 1;
    }
    if (exited > 0) {
      continue;
    }
    if (exited < 0 && errno != EINTR && errno != ECHILD) {
      stop_children(daemon, supervisor);
      return 1;
    }
    short_pause();
  }
  {
    int signal_number = shutdown_signal;
    stop_children(daemon, supervisor);
    return 128 + signal_number;
  }
}

static bool install_signal_handlers(void) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = remember_signal;
  sigemptyset(&action.sa_mask);
  return sigaction(SIGTERM, &action, NULL) == 0 &&
         sigaction(SIGINT, &action, NULL) == 0 &&
         sigaction(SIGHUP, &action, NULL) == 0 &&
         sigaction(SIGQUIT, &action, NULL) == 0;
}

int main(int argc, char **argv) {
  struct sandbox_environment environment;
  pid_t daemon = -1;
  pid_t supervisor = -1;
  int daytona_listener = -1;
  bool listener_created = false;
  int result = 1;
  (void)argv;
  (void)umask(0077);
  if (argc != 1 || geteuid() != 0 || getegid() != 0 ||
      !capture_environment(&environment) ||
      !hostname_matches() || !validate_image_boundary() ||
      !confine_root_identity_and_capabilities() ||
      prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
      prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0 ||
      !install_signal_handlers()) {
    goto failure;
  }
  daytona_listener = create_daytona_listener();
  if (daytona_listener < 0) {
    goto failure;
  }
  listener_created = true;
  daemon = spawn_daytona(daytona_listener);
  (void)close(daytona_listener);
  daytona_listener = -1;
  if (daemon <= 0 || !wait_for_assignment(daemon)) {
    goto failure;
  }
  supervisor = spawn_supervisor(&environment);
  if (supervisor <= 0 || !wait_for_supervisor_socket(daemon, supervisor)) {
    goto failure;
  }
  result = supervise(daemon, supervisor);
  if (!remove_daytona_listener()) {
    result = 1;
  }
  return result;

failure:
  if (daytona_listener >= 0) {
    (void)close(daytona_listener);
  }
  stop_children(daemon, supervisor);
  if (listener_created) {
    (void)remove_daytona_listener();
  }
  {
    static const char failure_message[] = "TerminalX sandbox init failed closed\n";
    ssize_t ignored =
        write(STDERR_FILENO, failure_message, sizeof(failure_message) - 1);
    (void)ignored;
  }
  return result;
}
