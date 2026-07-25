#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/*
 * The accepted Unix socket is inherited only as fd 3.  stdout contains one
 * fixed-shape record; errors and peer-controlled values never enter it.
 */
int main(int argc, char **argv) {
  struct ucred peer;
  struct stat socket_stat;
  socklen_t length = sizeof(peer);
  struct sockaddr_un peer_address;
  socklen_t peer_address_length = sizeof(peer_address);
  int accepting = 1;
  socklen_t accepting_length = sizeof(accepting);

  (void)argv;
  if (argc != 1 || geteuid() != 0 || fcntl(3, F_GETFD) < 0 ||
      fstat(3, &socket_stat) != 0 || !S_ISSOCK(socket_stat.st_mode) ||
      getsockopt(3, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &accepting_length) != 0 ||
      accepting_length != sizeof(accepting) || accepting != 0 ||
      getpeername(3, (struct sockaddr *)&peer_address, &peer_address_length) != 0 ||
      peer_address_length < sizeof(sa_family_t) || peer_address.sun_family != AF_UNIX ||
      getsockopt(3, SOL_SOCKET, SO_PEERCRED, &peer, &length) != 0 ||
      length != sizeof(peer) || peer.pid <= 0) {
    return 78;
  }
  if (dprintf(STDOUT_FILENO, "{\"pid\":%ld,\"uid\":%ld,\"gid\":%ld}\n",
              (long)peer.pid, (long)peer.uid, (long)peer.gid) < 0) {
    return 74;
  }
  return 0;
}
