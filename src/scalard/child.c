/* 
 * We self-exec after cloning off the child process inside the container. This
 * completely disconnects the child process (us, PID 1 in the container) from
 * the daemon.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>

#include "fs.h"

/* Close all FDs greater than or equal to lowfd */
static int closefrom(int lowfd) {
  DIR *dir;
  struct dirent *dirent;

  if ((dir = opendir("/proc/self/fd")) != NULL) {
    while (errno = 0, dirent = readdir(dir)) {
      int fd;
      if (*dirent->d_name == '.')
        continue;
      fd = atoi(dirent->d_name);
      if (fd != dirfd(dir) && fd >= lowfd)
        close(fd);
    }
    closedir(dir);
  }
  return errno ? -1 : 0;
}

/* Configure the container's rootfs */
static int setup_root(void) {
  if (chdir("/") != 0 ||
      syscall(SYS_pivot_root, SCALAR_MOUNTPOINT,
              SCALAR_MOUNTPOINT SCALAR_MOUNTPOINT) != 0 ||
      chdir("/") != 0)
    return -1;
  return 0;
}

/* This is called from main when argv[0] == "__init" */
void child_init(char *argv[]) {
  pid_t pid;
  int wait_status;

  if (closefrom(3) != 0)
    err(EXIT_FAILURE, "closefrom");

  if (setup_root() != 0)
    err(EXIT_FAILURE, "setup_root");

  switch (pid = fork()) {
  case 0:
    execv(argv[1], &argv[1]);
    err(EXIT_FAILURE, "execv");

  case -1:
    err(EXIT_FAILURE, "fork");

  default:
    while (pid != wait(&wait_status));
    if (WIFSIGNALED(wait_status))
      fprintf(stderr, "Received signal %d\n", WTERMSIG(wait_status));
    exit(WIFEXITED(wait_status) ? WEXITSTATUS(wait_status) : 255);
  }
}
