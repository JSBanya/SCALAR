#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include <fuse_lowlevel.h>

#include "fs.h"

#include "event_loop.h"
#include "fs_ops.h"

struct fs_data {
  struct event_loop_handlers *h;
  struct fuse_session *se;
};

int fs_fd(void *arg) {
  struct fs_data *data = arg;
  return fuse_session_fd(data->se);
}

int fs_read(void *arg) {
  struct fs_data *data = arg;
  int res;
  struct fuse_buf buf = { 0 };

 retry:
  if ((res = fuse_session_receive_buf(data->se, &buf)) <= 0) {
    if (res == -EINTR)
      goto retry;
    if (res) {
      errno = -res;
      warn("fuse_session_receive_buf");
    }
  } else {
    fuse_session_process_buf(data->se, &buf);
  }

  free(buf.mem);

  if (fuse_session_exited(data->se))
    fs_free(data);

  return 0;
}

void fs_close(void *arg) {
  fs_free(arg);
}

struct event_loop_handlers fs_handlers = { .fd = fs_fd, .read = fs_read };

char *fuse_argv[] = { "", "-oallow_other", "-odefault_permissions", NULL };
struct fuse_args fuse_args = FUSE_ARGS_INIT(3, fuse_argv);

struct fs_data *fs_new() {
  struct fs_data *data;
  if ((data = malloc(sizeof(*data))) == NULL)
    return NULL;
  data->h = &fs_handlers;
  if ((data->se = fuse_session_new(&fuse_args, fs_ops_p, sizeof(*fs_ops_p), NULL)) == NULL) {
    int save_errno = errno;
    free(data);
    errno = save_errno;
    return NULL;
  }
  return data;
}

int fs_activate(struct fs_data *data) {
  if (mkdir(SCALAR_MOUNTPOINT, 0755) != 0 && errno != EEXIST)
    return -1;
  if (fuse_session_fd(data->se) == -1 &&
      fuse_session_mount(data->se, SCALAR_MOUNTPOINT) != 0)
    return -1;
  return event_loop_register(&data->h);
}

void fs_free(struct fs_data *data) {
  if (fuse_session_fd(data->se) != -1)
    fuse_session_unmount(data->se);
  fuse_session_destroy(data->se);
  free(data);
}
