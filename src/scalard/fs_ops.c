#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <limits.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include <fuse_lowlevel.h>

#include "fs_ops.h"

#include "log.h"

struct dir_data {
  int fd;
  DIR *dp;
  struct dirent *entry;
  off_t offset;
};

static struct dir_data *dir_data(struct fuse_file_info *fi) {
  return (struct dir_data *) (uintptr_t) fi->fh;
}

struct inode_data {
  struct inode_data *next; /* protected by scalar->mutex */
  struct inode_data *prev; /* protected by scalar->mutex */
  int fd;
  bool is_symlink;
  ino_t ino;
  dev_t dev;
  uint64_t refcount; /* protected by scalar->mutex */
  char *parent;
};

struct inode_data scalar_root =
  {
   .next = &scalar_root, .prev = &scalar_root,
   .fd = -1, .refcount = 2,
   .is_symlink = false
  };

// Get inode struct from fuse inode
static struct inode_data *inode_data(fuse_req_t req, fuse_ino_t ino) {
  if (ino == FUSE_ROOT_ID)
    return &scalar_root;
  else
    return (struct inode_data *) (uintptr_t) ino;
}

// Get file descriptor for inode
static int scalar_fd(fuse_req_t req, fuse_ino_t ino) {
  return inode_data(req, ino)->fd;
}

// Initialize filesystem
// This function is called when libfuse establishes communication with the FUSE kernel module
static void scalar_init(void *userdata, struct fuse_conn_info *conn) {
  conn->want |=
    (conn->capable & FUSE_CAP_EXPORT_SUPPORT) |
    (conn->capable & FUSE_CAP_FLOCK_LOCKS);
}

// Get file attributes
static void scalar_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  (void) fi;
  struct stat buf;
  int res = fstatat(scalar_fd(req, ino), "", &buf, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
  if (res == -1)
    return (void) fuse_reply_err(req, errno);
  fuse_reply_attr(req, &buf, 0);
}

static int utimensat_empty_nofollow(struct inode_data *inode, const struct timespec *tv) {
  int res;
  char procname[64];
  if (inode->is_symlink) {
    res = utimensat(inode->fd, "", tv, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
    if (res == -1 && errno == EINVAL) {
      errno = EPERM;
    }
    return res;
  }
  sprintf(procname, "/proc/self/fd/%i", inode->fd);
  return utimensat(AT_FDCWD, procname, tv, 0);
}

// Set file attributes
static void scalar_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi) {
  int saverr;
  char procname[64];
  struct inode_data *inode = inode_data(req, ino);
  int ifd = inode->fd;
  int res;

  // Get original attributes
  struct stat original;
  if (fi) {
    res = fstat(fi->fh, &original);
  } else {
    sprintf(procname, "/proc/self/fd/%i", ifd);
    res = stat(procname, &original);
  }

  if (res == -1)
    goto out_err;

  ino_t sys_ino = inode_data(req, ino)->ino;

  // Set attributes based on to_set
  if (to_set & FUSE_SET_ATTR_MODE) {
    if (fi) {
      res = fchmod(fi->fh, attr->st_mode);
    } else {
      sprintf(procname, "/proc/self/fd/%i", ifd);
      res = chmod(procname, attr->st_mode);
    }

    if (res == -1)
      goto out_err;

    log_setattr_chmod(sys_ino, &original, attr);
  }

  if (to_set & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
    uid_t uid = (to_set & FUSE_SET_ATTR_UID) ? attr->st_uid : (uid_t) -1;
    gid_t gid = (to_set & FUSE_SET_ATTR_GID) ? attr->st_gid : (gid_t) -1;
    res = fchownat(ifd, "", uid, gid, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
    if (res == -1)
      goto out_err;

    log_setattr_uid_or_gid(sys_ino, &original, attr);
  }

  if (to_set & FUSE_SET_ATTR_SIZE) {
    char *data_lost;
    off_t amount_lost = original.st_size - attr->st_size;
    if(amount_lost > 0) {
      // We must do extra work in this case to log any lost data from truncation
      data_lost = malloc(amount_lost+1);

      // The fd provided by fi->fh is opened with O_PATH, and thus unreadable
      // We must open the file manually with read permissions to get the data lost
      sprintf(procname, "/proc/self/fd/%i", ifd);
      int fd = open(procname, O_RDONLY);

      long cur = lseek(fd, 0, SEEK_CUR);
      lseek(fd, attr->st_size, SEEK_SET);
      ssize_t bytes_read = read(fd, data_lost, amount_lost);
      lseek(fd, cur, SEEK_SET);
      data_lost[amount_lost] = '\0';

      res = close(fd);
      if (res == -1) {
        free(data_lost);
        goto out_err;
      }

      if(bytes_read != amount_lost) {
        free(data_lost);
        goto out_err;
      }
    } else {
      data_lost = malloc(1 * sizeof(char));
      data_lost[0] = '\0';
    }

    if (fi) {
      res = ftruncate(fi->fh, attr->st_size);
    } else {
      sprintf(procname, "/proc/self/fd/%i", ifd);
      res = truncate(procname, attr->st_size);
    }
    if (res == -1) {
      free(data_lost);
      goto out_err;
    }

    log_setattr_truncate(sys_ino, original.st_size, attr->st_size, data_lost);
    free(data_lost);
  }

  if (to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
    struct timespec tv[2];
    tv[0].tv_sec = 0;
    tv[1].tv_sec = 0;
    tv[0].tv_nsec = UTIME_OMIT;
    tv[1].tv_nsec = UTIME_OMIT;
    if (to_set & FUSE_SET_ATTR_ATIME_NOW)
      tv[0].tv_nsec = UTIME_NOW;
    else if (to_set & FUSE_SET_ATTR_ATIME)
      tv[0] = attr->st_atim;
    if (to_set & FUSE_SET_ATTR_MTIME_NOW)
      tv[1].tv_nsec = UTIME_NOW;
    else if (to_set & FUSE_SET_ATTR_MTIME)
      tv[1] = attr->st_mtim;
    if (fi)
      res = futimens(fi->fh, tv);
    else
      res = utimensat_empty_nofollow(inode, tv);
    if (res == -1)
      goto out_err;
  }

  return scalar_getattr(req, ino, fi);
 out_err:
  saverr = errno;
  fuse_reply_err(req, saverr);
}

// Find inode in the linked list of inodes
static struct inode_data *scalar_find(struct stat *st) {
  struct inode_data *p;
  struct inode_data *ret = NULL;
  for (p = scalar_root.next; p != &scalar_root; p = p->next) {
    if (p->ino == st->st_ino && p->dev == st->st_dev) {
      assert(p->refcount > 0);
      ret = p;
      ret->refcount++;
      break;
    }
  }
  return ret;
}

// Look up an inode by name and add it to the linked list of inodes (if its not already present)
// Sets the attributes in e
static int scalar_do_lookup(fuse_req_t req, fuse_ino_t parent, const char *name, struct fuse_entry_param *e) {
  int newfd;
  int res;
  int saverr;
  struct inode_data *inode;
  memset(e, 0, sizeof(*e));
  e->attr_timeout = 0;
  e->entry_timeout = 0;
  newfd = openat(scalar_fd(req, parent), name, O_PATH | O_NOFOLLOW); // Get file descriptor for file name
  if (newfd == -1)
    goto out_err;
  res = fstatat(newfd, "", &e->attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW); // Get attributes for opened file
  if (res == -1)
    goto out_err;
  inode = scalar_find(&e->attr); // Find if inode exists in linked list
  if (inode) {
    // Inode already exists in the linked list
    close(newfd);
    newfd = -1;
  } else {
    // Create new inode entry from file attributes
    struct inode_data *prev, *next;
    saverr = ENOMEM;
    inode = calloc(1, sizeof(struct inode_data));
    if (!inode)
      goto out_err;
    inode->is_symlink = S_ISLNK(e->attr.st_mode);
    inode->refcount = 1;
    inode->fd = newfd;
    inode->ino = e->attr.st_ino;
    inode->dev = e->attr.st_dev;
    prev = &scalar_root;
    next = prev->next;
    next->prev = inode;
    inode->next = next;
    inode->prev = prev;
    prev->next = inode;
  }
  e->ino = (uintptr_t) inode;
  return 0;
 out_err:
  saverr = errno;
  if (newfd != -1)
    close(newfd);
  return saverr;
}

// Look up a directory entry by name and get its attributes
static void scalar_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
  struct fuse_entry_param e;
  int err;

  err = scalar_do_lookup(req, parent, name, &e); // Populates e with attributes
  if (err)
    fuse_reply_err(req, err);
  else {
    ino_t parent_sys_ino = inode_data(req, parent)->ino;
    log_lookup(parent_sys_ino, name, e.attr.st_ino);
    fuse_reply_entry(req, &e);
  }
}

// Remove 'n' references to an inode
static void unref_inode(struct inode_data *inode, uint64_t n) {
  if (!inode) return;
  assert(inode->refcount >= n);
  inode->refcount -= n;
  if (!inode->refcount) {
    // It is recommended to defer removal of the inode until the lookup count reaches zero
    struct inode_data *prev, *next;
    prev = inode->prev;
    next = inode->next;
    next->prev = prev;
    prev->next = next;
    close(inode->fd);
    free(inode);
  } else {
  }
}

// Forget references to a single inode
static void scalar_forget_one(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
  struct inode_data *inode = inode_data(req, ino);
  unref_inode(inode, nlookup);
}

// Helper function to encapsulate similar functionality of mknod, mkdir, and symlink into one function
static void scalar_mknod_symlink(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev, const char *link) {
  int newfd = -1;
  int res;
  int saverr;
  struct inode_data *dir = inode_data(req, parent);
  struct fuse_entry_param e;
  saverr = ENOMEM;
  if (S_ISDIR(mode))
    res = mkdirat(dir->fd, name, mode);
  else if (S_ISLNK(mode))
    res = symlinkat(link, dir->fd, name);
  else
    res = mknodat(dir->fd, name, mode, rdev);
  saverr = errno;
  if (res == -1)
    goto out;

  saverr = scalar_do_lookup(req, parent, name, &e);
  if (saverr)
    goto out;

  // Log if successful
  ino_t parent_sys_ino = inode_data(req, parent)->ino;
  if (S_ISDIR(mode)) {
    log_mkdir(parent_sys_ino, name, e.attr.st_ino);
  } else if(S_ISLNK(mode)) {
    // Get inode for symlink
    struct fuse_entry_param sym_e;
    saverr = scalar_do_lookup(req, parent, link, &sym_e);
    if(saverr)
      goto out;
    scalar_forget_one(req, sym_e.ino, 1);

    log_symlink(parent_sys_ino, name, e.attr.st_ino, link, sym_e.attr.st_ino);
  } else {
    log_mknod(parent_sys_ino, name);
  }

  fuse_reply_entry(req, &e);
  return;

 out:
  if (newfd != -1)
    close(newfd);
  fuse_reply_err(req, saverr);
}

// Create file node by name
static void scalar_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev) {
  scalar_mknod_symlink(req, parent, name, mode, rdev, NULL);
}

// Create a directory by name
static void scalar_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode) {
  scalar_mknod_symlink(req, parent, name, S_IFDIR | mode, 0, NULL);
}

// Create a symbolic link
static void scalar_symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name) {
  scalar_mknod_symlink(req, parent, name, S_IFLNK, 0, link);
}

// Helper function for scalar_link
static int linkat_empty_nofollow(struct inode_data *inode, int dfd, const char *name) {
  int res;
  char procname[64];
  if (inode->is_symlink) {
    res = linkat(inode->fd, "", dfd, name, AT_EMPTY_PATH);
    if (res == -1 && (errno == ENOENT || errno == EINVAL)) {
      errno = EPERM;
    }
    return res;
  }
  sprintf(procname, "/proc/self/fd/%i", inode->fd);
  return linkat(AT_FDCWD, procname, dfd, name, AT_SYMLINK_FOLLOW);
}

// Create a hard link
static void scalar_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t parent, const char *name) {
  int res;
  struct inode_data *inode = inode_data(req, ino);
  struct fuse_entry_param e;
  int saverr;
  memset(&e, 0, sizeof(struct fuse_entry_param));
  e.attr_timeout = 0;
  e.entry_timeout = 0;

  res = linkat_empty_nofollow(inode, scalar_fd(req, parent), name); // Create the hardlink
  if (res == -1)
    goto out_err;

  res = fstatat(inode->fd, "", &e.attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW); // Get attributes
  if (res == -1)
    goto out_err;

  inode->refcount++;
  e.ino = (uintptr_t) inode;

  ino_t parent_sys_ino = inode_data(req, parent)->ino;
  log_link(parent_sys_ino, name, e.attr.st_ino);

  fuse_reply_entry(req, &e);
  return;
 out_err:
  saverr = errno;
  fuse_reply_err(req, saverr);
}

// Remove a directory
static void scalar_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
  int res = unlinkat(scalar_fd(req, parent), name, AT_REMOVEDIR);
  if(res != -1) {
    // Log if successful
    // There is no point in logging the inode on directory removal so we purposefully avoid doing so
    ino_t parent_sys_ino = inode_data(req, parent)->ino;
    log_rmdir(parent_sys_ino, name);
    fuse_reply_err(req, 0);
  } else
    fuse_reply_err(req, errno);
}

// Rename a file
static void scalar_rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname, unsigned int flags) {
  if (flags) {
    fuse_reply_err(req, EINVAL);
    return;
  }

  // Lookup file to get inode for logging
  struct fuse_entry_param e;
  int err = scalar_do_lookup(req, parent, name, &e);
  if (err)
    fuse_reply_err(req, err);
  scalar_forget_one(req, e.ino, 1);

  // Rename
  int res = renameat(scalar_fd(req, parent), name, scalar_fd(req, newparent), newname);
  if(res != -1) {
    // Log only if success
    ino_t parent_sys_ino = inode_data(req, parent)->ino;
    ino_t new_parent_sys_ino = inode_data(req, newparent)->ino;
    log_rename(parent_sys_ino, name, new_parent_sys_ino, newname, e.attr.st_ino);
    fuse_reply_err(req, 0);
  } else {
    fuse_reply_err(req, errno);
  }
}

// Remove a file
static void scalar_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) { 
  int parent_fd = scalar_fd(req, parent);

  // Get contents
  struct fuse_entry_param e;
  int res = scalar_do_lookup(req, parent, name, &e);
  if (res)
    goto out_err;
  scalar_forget_one(req, e.ino, 1);

  // Get file contents
  ssize_t file_size = e.attr.st_size;
  char *content = malloc(file_size+1);

  int fd = openat(parent_fd, name, O_RDONLY);
  lseek(fd, 0, SEEK_SET);
  ssize_t bytes_read = read(fd, content, file_size);
  content[file_size] = '\0';

  res = close(fd);
  if (res == -1 || bytes_read != file_size) {
    free(content);
    goto out_err;
  }

  // Unlink
  res = unlinkat(parent_fd, name, 0);
  if(res != -1) {
    // Log if successful
    ino_t parent_sys_ino = inode_data(req, parent)->ino;

    log_unlink(parent_sys_ino, e.attr.st_ino, name, content);
    fuse_reply_err(req, 0);
    return;
  }
  
 out_err:
  fuse_reply_err(req, errno);
}

// Forget about an inode
// This function is called when the kernel removes an inode from its internal caches
// The inode's lookup count increases by one for every call to fuse_reply_entry and fuse_reply_create 
// The nlookup parameter indicates by how much the lookup count should be decreased.
static void scalar_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
  scalar_forget_one(req, ino, nlookup);
  fuse_reply_none(req);
}

// Forget about multiple inodes
// See description of the forget function for more information
static void scalar_forget_multi(fuse_req_t req, size_t count, struct fuse_forget_data *forgets) {
  for (int i = 0; i < count; i++)
    scalar_forget_one(req, forgets[i].ino, forgets[i].nlookup);
  fuse_reply_none(req);
}

// Read symbolic link
static void scalar_readlink(fuse_req_t req, fuse_ino_t ino) {
  char buf[PATH_MAX + 1];
  int res = readlinkat(scalar_fd(req, ino), "", buf, sizeof(buf));
  if (res == -1)
    return (void) fuse_reply_err(req, errno);
  if (res == sizeof(buf))
    return (void) fuse_reply_err(req, ENAMETOOLONG);
  buf[res] = '\0';
  fuse_reply_readlink(req, buf);
}

// Open a directory
static void scalar_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  int error = ENOMEM;
  struct dir_data *d = calloc(1, sizeof(struct dir_data));
  if (d == NULL)
    goto out_err;
  d->fd = openat(scalar_fd(req, ino), ".", O_RDONLY);
  if (d->fd == -1)
    goto out_errno;
  d->dp = fdopendir(d->fd);
  if (d->dp == NULL)
    goto out_errno;
  d->offset = 0;
  d->entry = NULL;
  fi->fh = (uintptr_t) d;
  fuse_reply_open(req, fi);
  return;
 out_errno:
  error = errno;
 out_err:
  if (d) {
    if (d->fd != -1)
      close(d->fd);
    free(d);
  }
  fuse_reply_err(req, error);
}

static int is_dot_or_dotdot(const char *name) {
  return name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

// Helper function for readdir
static void scalar_do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi, int plus) {
  struct dir_data *d = dir_data(fi);
  char *buf;
  char *p;
  size_t rem = size;
  int err;
  (void) ino;
  buf = calloc(1, size);
  if (!buf) {
    err = ENOMEM;
    goto error;
  }
  p = buf;
  if (offset != d->offset) {
    seekdir(d->dp, offset);
    d->entry = NULL;
    d->offset = offset;
  }
  while (1) {
    size_t entsize;
    off_t nextoff;
    const char *name;
    if (!d->entry) {
      errno = 0;
      d->entry = readdir(d->dp);
      if (!d->entry) {
        if (errno) {  // Error
          err = errno;
          goto error;
        } else {  // End of stream
          break; 
        }
      }
    }
    nextoff = d->entry->d_off;
    name = d->entry->d_name;
    fuse_ino_t entry_ino = 0;
    if (plus) {
      struct fuse_entry_param e;
      if (is_dot_or_dotdot(name)) {
        e = (struct fuse_entry_param)
          {
           .attr.st_ino = d->entry->d_ino,
           .attr.st_mode = d->entry->d_type << 12,
          };
      } else {
        err = scalar_do_lookup(req, ino, name, &e);
        if (err)
          goto error;
        entry_ino = e.ino;
      }
      entsize = fuse_add_direntry_plus(req, p, rem, name, &e, nextoff);
    } else {
      struct stat st =
        {
         .st_ino = d->entry->d_ino,
         .st_mode = d->entry->d_type << 12,
        };
      entsize = fuse_add_direntry(req, p, rem, name, &st, nextoff);
    }
    if (entsize > rem) {
      if (entry_ino != 0) 
        scalar_forget_one(req, entry_ino, 1);
      break;
    }
    
    p += entsize;
    rem -= entsize;
    d->entry = NULL;
    d->offset = nextoff;
  }
  err = 0;
 error:
  // If there's an error, we can only signal it if we haven't stored
  // any entries yet - otherwise we'd end up with wrong lookup
  // counts for the entries that are already in the buffer. So we
  // return what we've collected until that point.
  if (err && rem == size)
    fuse_reply_err(req, err);
  else
    fuse_reply_buf(req, buf, size - rem);
  free(buf);
}

// Read directory
static void scalar_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi) {
  scalar_do_readdir(req, ino, size, offset, fi, 0);
}

// Read directory with attributes
// In contrast to readdir() (which does not affect the lookup counts), the lookup count of every entry returned by readdirplus(), except "." and "..", is incremented by one
static void scalar_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi) {
  scalar_do_readdir(req, ino, size, offset, fi, 1);
}

// Release an open directory
// For every opendir call there will be exactly one releasedir call (unless the filesystem is force-unmounted).
static void scalar_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  struct dir_data *d = dir_data(fi);
  (void) ino;
  closedir(d->dp);
  free(d);
  fuse_reply_err(req, 0);
}

// Create and open a file
// If the file does not exist, first create it with the specified mode, and then open it.
static void scalar_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi) {
  int fd;
  struct fuse_entry_param e;
  int err;

  // Test for file existence (to log only creates)
  int not_exists = faccessat(scalar_fd(req, parent), name, F_OK, AT_EACCESS | AT_SYMLINK_NOFOLLOW);

  // Open/create file
  fd = openat(scalar_fd(req, parent), name, (fi->flags | O_CREAT) & ~O_NOFOLLOW, mode);
  if (fd == -1)
    return (void) fuse_reply_err(req, errno);
  fi->fh = fd;
  fi->direct_io = 1;
  err = scalar_do_lookup(req, parent, name, &e);

  if (err)
    fuse_reply_err(req, err);
  else {
    // Log file creation
    if(not_exists) {
      ino_t parent_sys_ino = inode_data(req, parent)->ino;
      log_create(parent_sys_ino, name, e.attr.st_ino);
    }

    // Reply
    fuse_reply_create(req, &e, fi);
  }
}

// Synchronize directory contents
// If the datasync parameter is non-zero, then only the directory contents should be flushed, not the meta data.
static void scalar_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi) {
  int res;
  int fd = dirfd(dir_data(fi)->dp);
  (void) ino;
  if (datasync)
    res = fdatasync(fd);
  else
    res = fsync(fd);
  fuse_reply_err(req, res == -1 ? errno : 0);
}

// Open a file
// Open flags are available in fi->flags
static void scalar_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  int fd;
  char buf[64];

  sprintf(buf, "/proc/self/fd/%i", scalar_fd(req, ino));
  fd = open(buf, fi->flags & ~O_NOFOLLOW);
  if (fd == -1)
    return (void) fuse_reply_err(req, errno);
  fi->fh = fd;
  fi->direct_io = 1;
  fuse_reply_open(req, fi);
}

// Release an open file
// Release is called when there are no more references to an open file: all file descriptors are closed and all memory mappings are unmapped
// For every open call there will be exactly one release call (unless the filesystem is force-unmounted)
static void scalar_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  (void) ino;
  close(fi->fh);
  fuse_reply_err(req, 0);
}

// Flush method
// This is called on each close() of the opened file
// Since file descriptors can be duplicated (dup, dup2, fork), for one open call there may be many flush calls
static void scalar_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  (void) ino;
  int res = close(dup(fi->fh));
  fuse_reply_err(req, res == -1 ? errno : 0);
}

// Synchronize file contents
static void scalar_fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi) {
  int res;
  (void) ino;
  if (datasync)
    res = fdatasync(fi->fh);
  else
    res = fsync(fi->fh);
  fuse_reply_err(req, res == -1 ? errno : 0);
}

// Read data
// Read should send exactly the number of bytes requested except on EOF or error, otherwise the rest of the data will be substituted with zeroes
static void scalar_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi) {
  struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
  buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
  buf.buf[0].fd = fi->fh;
  buf.buf[0].pos = offset;
  fuse_reply_data(req, &buf, FUSE_BUF_SPLICE_MOVE);
}

// Write data made available in a buffer
// This is a more generic version of the write method
static void scalar_write_buf(fuse_req_t req, fuse_ino_t ino, struct fuse_bufvec *in_buf, off_t off, struct fuse_file_info *fi) {
  (void) ino;
  ssize_t res;
  struct fuse_bufvec out_buf = FUSE_BUFVEC_INIT(fuse_buf_size(in_buf));
  out_buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
  out_buf.buf[0].fd = fi->fh;
  out_buf.buf[0].pos = off;

  // Log write
  ino_t sys_ino = inode_data(req, ino)->ino;
  log_write_buf(sys_ino, in_buf, off);

  res = fuse_buf_copy(&out_buf, in_buf, 0);
  if(res < 0)
    fuse_reply_err(req, -res);
  else
    fuse_reply_write(req, (size_t) res);
}

// Get file system statistics
static void scalar_statfs(fuse_req_t req, fuse_ino_t ino) {
  struct statvfs stbuf;
  int res = fstatvfs(scalar_fd(req, ino), &stbuf);
  if (res == -1)
    fuse_reply_err(req, errno);
  else
    fuse_reply_statfs(req, &stbuf);
}

// Allocate requested space
// If this function returns success then subsequent writes to the specified range shall not fail due to the lack of free space on the file system storage media
static void scalar_fallocate(fuse_req_t req, fuse_ino_t ino, int mode, off_t offset, off_t length, struct fuse_file_info *fi) {
  int err;
  if (mode) {
    fuse_reply_err(req, EOPNOTSUPP);
    return;
  }

  struct stat attr;
  err = fstat(fi->fh, &attr);
  if (err == -1) {
    goto out;
  }

  err = posix_fallocate(fi->fh, offset, length);
  if(!err) {
    ino_t sys_ino = inode_data(req, ino)->ino;
    log_fallocate(sys_ino, attr.st_size, offset, length);
  }

 out:
  fuse_reply_err(req, err);
}

// Acquire, modify or release a BSD file lock
static void scalar_flock(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, int op) {
  int res;
  (void) ino;
  res = flock(fi->fh, op);
  fuse_reply_err(req, res == -1 ? errno : 0);
}

// Get an extended attribute by name
static void scalar_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size) {
  char *value = NULL;
  char procname[64];
  struct inode_data *inode = inode_data(req, ino);
  ssize_t ret;
  int saverr;
  saverr = ENOSYS;
  if (inode->is_symlink) {
    saverr = EPERM;
    goto out;
  }
  sprintf(procname, "/proc/self/fd/%i", inode->fd);
  if (size) {
    value = malloc(size);
    if (!value)
      goto out_err;
    ret = getxattr(procname, name, value, size);
    if (ret == -1)
      goto out_err;
    saverr = 0;
    if (ret == 0)
      goto out;
    fuse_reply_buf(req, value, ret);
  } else {
    ret = getxattr(procname, name, NULL, 0);
    if (ret == -1)
      goto out_err;
    fuse_reply_xattr(req, ret);
  }
 out_free:
  free(value);
  return;
 out_err:
  saverr = errno;
 out:
  fuse_reply_err(req, saverr);
  goto out_free;
}

// List extended attribute names
static void scalar_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size) {
  char *value = NULL;
  char procname[64];
  struct inode_data *inode = inode_data(req, ino);
  ssize_t ret;
  int saverr;
  saverr = ENOSYS;
  if (inode->is_symlink) {
    saverr = EPERM;
    goto out;
  }
  sprintf(procname, "/proc/self/fd/%i", inode->fd);
  if (size) {
    value = malloc(size);
    if (!value)
      goto out_err;
    ret = listxattr(procname, value, size);
    if (ret == -1)
      goto out_err;
    saverr = 0;
    if (ret == 0)
      goto out;
    fuse_reply_buf(req, value, ret);
  } else {
    ret = listxattr(procname, NULL, 0);
    if (ret == -1)
      goto out_err;
    fuse_reply_xattr(req, ret);
  }
 out_free:
  free(value);
  return;
 out_err:
  saverr = errno;
 out:
  fuse_reply_err(req, saverr);
  goto out_free;
}

// Set an extended attribute
static void scalar_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name, const char *value, size_t size, int flags) {
  char procname[64];
  struct inode_data *inode = inode_data(req, ino);
  ssize_t ret;
  int saverr;
  saverr = ENOSYS;
  if (inode->is_symlink) {
    saverr = EPERM;
    goto out;
  }
  sprintf(procname, "/proc/self/fd/%i", inode->fd);

  // Get old value if it exists
  ssize_t xattr_size = getxattr(procname, name, 0, 0);
  char *old_value;
  if(xattr_size == -1) {
    if(errno != ENODATA) {
      saverr = errno;
      goto out;
    }
  
    old_value = malloc(1);
    old_value[0] = '\0';
  } else {
    old_value = malloc(xattr_size+1);
    ssize_t xattr_size_read = getxattr(procname, name, old_value, xattr_size);
    old_value[xattr_size] = '\0';

    if(xattr_size_read != xattr_size) {
      free(old_value);
      saverr = errno;
      goto out;
    }
  }

  ret = setxattr(procname, name, value, size, flags);
  saverr = ret == -1 ? errno : 0;

  if(!saverr) {
    ino_t sys_ino = inode_data(req, ino)->ino;
    log_setxattr(sys_ino, name, old_value, value);
  }
  free(old_value);

 out:
  fuse_reply_err(req, saverr);
}

// Remove an extended attribute
static void scalar_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name) {
  char procname[64];
  struct inode_data *inode = inode_data(req, ino);
  ssize_t ret;
  int saverr;
  saverr = ENOSYS;

  if (inode->is_symlink) {
    saverr = EPERM;
    goto out;
  }
  sprintf(procname, "/proc/self/fd/%i", inode->fd);

  // Get old value
  ssize_t xattr_size = getxattr(procname, name, 0, 0);
  if(xattr_size == -1) {
    saverr = errno;
    goto out;
  } 

  char *old_value = malloc(xattr_size+1);
  ssize_t xattr_size_read = getxattr(procname, name, old_value, xattr_size);
  old_value[xattr_size] = '\0';

  if(xattr_size_read != xattr_size) {
    free(old_value);
    saverr = errno;
    goto out;
  }

  ret = removexattr(procname, name);
  saverr = ret == -1 ? errno : 0;

  if(!saverr) {
    ino_t sys_ino = inode_data(req, ino)->ino;
    log_removexattr(sys_ino, name, old_value);
  }
  free(old_value);

 out:
  fuse_reply_err(req, saverr);
}

const struct fuse_lowlevel_ops fs_ops =
  {
   .init           = scalar_init,
   .destroy        = NULL,
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
const struct fuse_lowlevel_ops *fs_ops_p = &fs_ops;

void fs_ops_init() {
  if ((scalar_root.fd = open("/", O_PATH)) < 0)
    err(EXIT_FAILURE, "open(/)");
}
