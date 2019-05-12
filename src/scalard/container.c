#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include <fcntl.h>
#include <sched.h>
#include <semaphore.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "container.h"

#include "fs.h"

struct child_data {
  char **argv;
  int *stdfds;
  struct fs_data *fs_data;
  sem_t semaphore;
  int pipefds[2];
};

int child_task(void *arg) {
  struct child_data *data = arg;
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
    int save_errno = errno;
    fs_free(data->fs_data);
    sem_post(&data->semaphore);
    errno = save_errno;
    err(EXIT_FAILURE, "mount(/, rprivate)");
  }
  if (fs_activate(data->fs_data) != 0) {
    int save_errno = errno;
    fs_free(data->fs_data);
    sem_post(&data->semaphore);
    errno = save_errno;
    err(EXIT_FAILURE, "fs_activate");
  }
  fflush(stdout);
  fflush(stderr);
  if (pipe2(data->pipefds, O_CLOEXEC) != 0) {
    sem_post(&data->semaphore);
    err(EXIT_FAILURE, "pipe");
  }
  if (unshare(CLONE_FILES) != 0) {
    sem_post(&data->semaphore);
    err(EXIT_FAILURE, "unshare");
  }
  if (sem_post(&data->semaphore) != 0)
    err(EXIT_FAILURE, "sem_post");
  close(data->pipefds[0]);
  if (dup2(data->stdfds[0], 0) < 0 ||
      dup2(data->stdfds[1], 1) < 0 ||
      dup2(data->stdfds[2], 2) < 0)
    err(EXIT_FAILURE, "dup2");

  umask(0022);

  execv("/proc/self/exe", data->argv);
  err(EXIT_FAILURE, "execv");
}

void container_start(char **argv, int *stdfds) {
  unsigned char child_stack[4096];
  struct child_data child = { .argv = argv, .stdfds = stdfds };
  char dummy_buf;

  if (sem_init(&child.semaphore, 0, 0) != 0) {
    warn("sem_init");
    return;
  }

  if ((child.fs_data = fs_new()) == NULL) {
    warn("fs_new");
    sem_destroy(&child.semaphore);
    return;
  }

  if (clone(child_task, child_stack + sizeof(child_stack),
            CLONE_FILES | CLONE_NEWNS | CLONE_NEWPID | CLONE_VM,
            &child) == -1)
    warn("clone");

 wait_longer:
  if (sem_wait(&child.semaphore) != 0) {
    if (errno == EINTR)
      goto wait_longer;
    else
      warn("sem_wait");
  }
  sem_destroy(&child.semaphore);
  close(child.pipefds[1]);
  while (read(child.pipefds[0], &dummy_buf, 1) != 0 && (errno == EINTR));
}
