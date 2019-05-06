#ifndef SCALAR_FUSE_H
#define SCALAR_FUSE_H
	
#define _GNU_SOURCE
#define FUSE_USE_VERSION 31
#include <fuse_lowlevel.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/file.h>
#include <sys/xattr.h>

struct scalar_inode {
    struct scalar_inode *next; /* protected by scalar->mutex */
    struct scalar_inode *prev; /* protected by scalar->mutex */
    int fd;
    bool is_symlink;
    ino_t ino;
    dev_t dev;
    uint64_t refcount; /* protected by scalar->mutex */
    char *parent;
};

/* We are re-using pointers to our `struct scalar_inode` and `struct
   scalar_dirp` elements as inodes. This means that we must be able to
   store uintptr_t values in a fuse_ino_t variable. The following
   incantation checks this condition at compile time.*/
#if defined(__GNUC__) && (__GNUC__ > 4 || __GNUC__ == 4 && __GNUC_MINOR__ >= 6) && !defined __cplusplus
_Static_assert(sizeof(fuse_ino_t) >= sizeof(uintptr_t), "fuse_ino_t too small to hold uintptr_t values!");
#endif

enum {
    CACHE_NEVER,
    CACHE_NORMAL,
    CACHE_ALWAYS,
};

struct scalar_data {
    pthread_mutex_t mutex;
    int debug;
    int writeback;
    int flock;
    int xattr;
    const char *source;
    double timeout;
    int cache;
    int timeout_set;
    struct scalar_inode root; /* protected by scalar->mutex */
};

static const struct fuse_opt scalar_opts[] = {
    { "writeback",
      offsetof(struct scalar_data, writeback), 1 },
    { "no_writeback",
      offsetof(struct scalar_data, writeback), 0 },
    { "source=%s",
      offsetof(struct scalar_data, source), 0 },
    { "flock",
      offsetof(struct scalar_data, flock), 1 },
    { "no_flock",
      offsetof(struct scalar_data, flock), 0 },
    { "xattr",
      offsetof(struct scalar_data, xattr), 1 },
    { "no_xattr",
      offsetof(struct scalar_data, xattr), 0 },
    { "timeout=%lf",
      offsetof(struct scalar_data, timeout), 0 },
    { "timeout=",
      offsetof(struct scalar_data, timeout_set), 1 },
    { "cache=never",
      offsetof(struct scalar_data, cache), CACHE_NEVER },
    { "cache=auto",
      offsetof(struct scalar_data, cache), CACHE_NORMAL },
    { "cache=always",
      offsetof(struct scalar_data, cache), CACHE_ALWAYS },
    FUSE_OPT_END
};

struct scalar_dirp {
    int fd;
    DIR *dp;
    struct dirent *entry;
    off_t offset;
};

static struct scalar_dirp *scalar_dirp(struct fuse_file_info *fi);
static struct scalar_data *scalar_data(fuse_req_t req);
static struct scalar_inode *scalar_inode(fuse_req_t req, fuse_ino_t ino);
static int scalar_fd(fuse_req_t req, fuse_ino_t ino);
static bool scalar_debug(fuse_req_t req);
static void scalar_init(void *userdata, struct fuse_conn_info *conn);
static void scalar_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static int utimensat_empty_nofollow(struct scalar_inode *inode, const struct timespec *tv);
static void scalar_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi);
static struct scalar_inode *scalar_find(struct scalar_data *scalar, struct stat *st);
static int scalar_do_lookup(fuse_req_t req, fuse_ino_t parent, const char *name, struct fuse_entry_param *e);
static void scalar_lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
static void scalar_mknod_symlink(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev, const char *link);
static void scalar_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev);
static void scalar_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode);
static void scalar_symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name);
static int linkat_empty_nofollow(struct scalar_inode *inode, int dfd, const char *name);
static void scalar_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t parent, const char *name);
static void scalar_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name);
static void scalar_rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname, unsigned int flags);
static void scalar_unlink(fuse_req_t req, fuse_ino_t parent, const char *name);
static void unref_inode(struct scalar_data *scalar, struct scalar_inode *inode, uint64_t n);
static void scalar_forget_one(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup);
static void scalar_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup);
static void scalar_forget_multi(fuse_req_t req, size_t count, struct fuse_forget_data *forgets);
static void scalar_readlink(fuse_req_t req, fuse_ino_t ino);
static void scalar_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static int is_dot_or_dotdot(const char *name);
static void scalar_do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi, int plus);
static void scalar_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi);
static void scalar_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi);
static void scalar_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void scalar_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi);
static void scalar_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi);
static void scalar_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void scalar_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void scalar_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
static void scalar_fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi);
static void scalar_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi);
static void scalar_write_buf(fuse_req_t req, fuse_ino_t ino, struct fuse_bufvec *in_buf, off_t off, struct fuse_file_info *fi);
static void scalar_statfs(fuse_req_t req, fuse_ino_t ino);
static void scalar_fallocate(fuse_req_t req, fuse_ino_t ino, int mode, off_t offset, off_t length, struct fuse_file_info *fi);
static void scalar_flock(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, int op);
static void scalar_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size);
static void scalar_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size);
static void scalar_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name, const char *value, size_t size, int flags);
static void scalar_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name);


static struct fuse_lowlevel_ops scalar_oper = {
        .init           = scalar_init,
        .lookup         = scalar_lookup,
        .mkdir          = scalar_mkdir,
        .mknod          = scalar_mknod,
        .symlink        = scalar_symlink,
        .link           = scalar_link,
        .unlink         = scalar_unlink,
        .rmdir          = scalar_rmdir,
        .rename         = scalar_rename,
        .forget         = scalar_forget,
        .forget_multi   = scalar_forget_multi,
        .getattr        = scalar_getattr,
        .setattr        = scalar_setattr,
        .readlink       = scalar_readlink,
        .opendir        = scalar_opendir,
        .readdir        = scalar_readdir,
        .readdirplus    = scalar_readdirplus,
        .releasedir     = scalar_releasedir,
        .fsyncdir       = scalar_fsyncdir,
        .create         = scalar_create,
        .open           = scalar_open,
        .release        = scalar_release,
        .flush          = scalar_flush,
        .fsync          = scalar_fsync,
        .read           = scalar_read,
        .write_buf      = scalar_write_buf,
        .statfs         = scalar_statfs,
        .fallocate      = scalar_fallocate,
        .flock          = scalar_flock,
        .getxattr       = scalar_getxattr,
        .listxattr      = scalar_listxattr,
        .setxattr       = scalar_setxattr,
        .removexattr    = scalar_removexattr,
};

#endif