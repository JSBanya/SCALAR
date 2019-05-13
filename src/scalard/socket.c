#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "socket.h"

#include "container.h"
#include "event_loop.h"

/* 
 * A client must send a message consisting of the argv for the child process as
 * a series of null-terminated strings, separated by a non-null character (by
 * convention a space) and finally terminated by an extra trailing null. The
 * full path for argv[0] must be used, as it will be reused as the executable
 * path. For example:
 *   /bin/echo foo bar => ' /bin/echo\0 foo\0 bar\0\0'
 * A client may optionally attach three file descriptors to the message; these
 * file descriptors will be used as stdin, stdout, and stderr for the child
 * process. Otherwise, /dev/null will be used.
 */

int sockfd;

struct conn_data {
  struct event_loop_handlers *h;
  char **argv;
  size_t argv_pos, argv_len, str_len;
  int fd;
  int stdfds[3];
};

static int conn_fd(void *arg) {
  struct conn_data *data = arg;
  return data->fd;
}

static int conn_read(void *arg) {
  struct conn_data *data = arg;
  char buf[4096];
  size_t buf_pos = 0;
  ssize_t buf_len;

  struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
  union { char cbuf[CMSG_SPACE(sizeof(data->stdfds))]; struct cmsghdr align; } u;
  struct msghdr msghdr =
    { .msg_iov = &iov, .msg_iovlen = 1,
      .msg_control = &u.cbuf, .msg_controllen = sizeof(u.cbuf) };

 retry_read:
  if ((buf_len = recvmsg(data->fd, &msghdr, MSG_CMSG_CLOEXEC)) < 0) {
    if (errno == EINTR)
      goto retry_read;
    warn("recvmsg");
    return -1;
  }

  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msghdr);
       cmsg != NULL; cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
    if (cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_RIGHTS) {
      int *recv_fds = (int *) CMSG_DATA(cmsg),
        *recv_fds_end = (int *) (((unsigned char *) cmsg) + cmsg->cmsg_len);
      for (size_t i = 0; recv_fds + i < recv_fds_end; ++i) {
        if (i < sizeof(data->stdfds) / sizeof(*data->stdfds)) {
          close(data->stdfds[i]);
          data->stdfds[i] = recv_fds[i];
        } else {
          close(recv_fds[i]);
        }
      }
    }
  }

  while (buf_pos < (size_t) buf_len) {
    if (data->str_len == 0 && data->argv[data->argv_pos] != NULL) {
      if (++data->argv_pos >= data->argv_len) {
        char **new_argv;
        if ((new_argv =
             realloc(data->argv, (data->argv_len *= 2) * sizeof(*data->argv)))
            == NULL) {
          warn("realloc");
          --data->argv_pos;
          return -1;
        }
        data->argv = new_argv;
      }
      data->argv[data->argv_pos] = NULL;
      if (buf[buf_pos++] == '\0') {
        container_start(data->argv, data->stdfds);
        return -1;
      }
    } else {
      char *end = memchr(buf + buf_pos, '\0', buf_len - buf_pos);
      size_t len = end == NULL ? (size_t) buf_len - buf_pos : (size_t) (end - (buf + buf_pos)) + 1;
      char *new_str;

      if ((new_str =
           realloc(data->argv[data->argv_pos], data->str_len + len))
          == NULL) {
        warn("realloc");
        return -1;
      }
      data->argv[data->argv_pos] = new_str;
      memcpy(new_str + data->str_len, buf + buf_pos, len);
      buf_pos += len;
      if (end)
        data->str_len = 0;
      else
        data->str_len += len;
    }
  }

  return 0;
}

static void conn_close(void *arg) {
  struct conn_data *data = arg;
  for (size_t i = 1, pos = data->argv_pos; i <= pos; ++i)
    free(data->argv[i]);
  free(data->argv);
  close(data->fd);
  for (size_t i = 0; i < sizeof(data->stdfds) / sizeof(*data->stdfds); ++i)
    close(data->stdfds[i]);
  free(data);
}

struct event_loop_handlers conn_handlers =
  { .fd = conn_fd, .read = conn_read, .close = conn_close };

struct conn_data *conn_data_new(int fd) {
  struct conn_data *data;
  if ((data = malloc(sizeof(*data))) == NULL)
    return NULL;
  data->h = &conn_handlers;
  data->argv_len = 128;
  if ((data->argv = malloc(data->argv_len * sizeof(*data->argv))) == NULL) {
    free(data);
    return NULL;
  }
  data->argv_pos = data->str_len = 0;
  data->argv[data->argv_pos] = "__init";
  data->fd = fd;
  for (size_t i = 0; i < sizeof(data->stdfds) / sizeof(*data->stdfds); ++i)
    data->stdfds[i] = -1;
  return data;
}

static int socket_fd(void *arg) {
  (void) arg;
  return sockfd;
}

static int socket_accept(void *arg) {
  (void) arg;

  int fd;
  struct conn_data *data;

  if ((fd = accept(sockfd, NULL, NULL)) < 0) {
    warn("accept");
    return 0;
  }

  if ((data = conn_data_new(fd)) == NULL) {
    warn("conn_data_new");
    goto out_close;
  }

  if (event_loop_register(&data->h) != 0) {
    warn("event_loop_register");
    free(data);
  } else {
    return 0;
  }

 out_close:
  close(fd);
  return 0;
}

struct event_loop_handlers socket_handlers =
  { .fd = socket_fd, .read = socket_accept };
struct event_loop_handlers *socket_handlers_p = &socket_handlers;

void socket_init() {
  struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = "/run/scalar.sock" };
  unlink(addr.sun_path);
  if ((sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0)
    err(EXIT_FAILURE, "socket(AF_UNIX)");
  if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) != 0)
    err(EXIT_FAILURE, "bind(/run/scalar.sock)");
  if (listen(sockfd, 0) != 0)
    err(EXIT_FAILURE, "listen(/run/scalar.sock)");
  if (event_loop_register(&socket_handlers_p) != 0)
    err(EXIT_FAILURE, "event_loop_register");
}
