#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>

#include <sys/socket.h>
#include <sys/un.h>

int main(int argc, char **argv) {
  int sockfd;
  size_t buflen = 1;
  char *buf, *bufp;
  struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = "/run/scalar.sock" };

  if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    err(EXIT_FAILURE, "socket");
  if ((connect(sockfd, (struct sockaddr *) &addr, sizeof(addr))) != 0)
    err(EXIT_FAILURE, "connect(/run/scalar.sock)");

  for (int i = 1; i < argc; ++i)
    buflen += strlen(argv[i]) + 2;
  if ((bufp = buf = malloc(buflen)) == NULL)
    err(EXIT_FAILURE, "malloc");

  for (int i = 1; i < argc; ++i) {
    *(bufp++) = ' ';
    bufp = stpcpy(bufp, argv[i]) + 1;
  }
  *bufp = '\0';
  bufp = buf;

  while (bufp < buf + buflen) {
    ssize_t sendmsg_len;
    struct iovec iovec = { .iov_base = bufp, .iov_len = buf + buflen - bufp };
    struct msghdr msg = { .msg_iov = &iovec, .msg_iovlen = 1 };

    int stdfds[] = { 0, 1, 2 };
    union {
      char buf[CMSG_SPACE(sizeof(stdfds))];
      struct cmsghdr align;
    } u;

    if (bufp == buf) {
      struct cmsghdr *cmsg;
      msg.msg_control = &u;
      msg.msg_controllen = sizeof(u);
      cmsg = CMSG_FIRSTHDR(&msg);
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      cmsg->cmsg_len = CMSG_LEN(sizeof(stdfds));
      memcpy(CMSG_DATA(cmsg), stdfds, sizeof(stdfds));
    }

    if ((sendmsg_len = sendmsg(sockfd, &msg, 0)) == -1)
      err(EXIT_FAILURE, "sendmsg");
    bufp += sendmsg_len;
  }
}
