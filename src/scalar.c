#include "scalar.h"
#include "log.h"

static struct scalar_dirp *scalar_dirp(struct fuse_file_info *fi) {
	return (struct scalar_dirp *) (uintptr_t) fi->fh;
}

// Get user data from the request
static struct scalar_data *scalar_data(fuse_req_t req) {
	return (struct scalar_data *) fuse_req_userdata(req);
}

// Get inode struct from fuse inode
static struct scalar_inode *scalar_inode(fuse_req_t req, fuse_ino_t ino) {
	if (ino == FUSE_ROOT_ID)
		return &scalar_data(req)->root;
	else
		return (struct scalar_inode *) (uintptr_t) ino;
}

// Get file descriptor for inode
static int scalar_fd(fuse_req_t req, fuse_ino_t ino) {
	return scalar_inode(req, ino)->fd;
}

// Check if debug is enabled
static bool scalar_debug(fuse_req_t req) {
	return scalar_data(req)->debug != 0;
}

// Initialize filesystem
// This function is called when libfuse establishes communication with the FUSE kernel module
static void scalar_init(void *userdata, struct fuse_conn_info *conn) {
	struct scalar_data *scalar = (struct scalar_data*) userdata;
	if(conn->capable & FUSE_CAP_EXPORT_SUPPORT)
		conn->want |= FUSE_CAP_EXPORT_SUPPORT;
	if (scalar->writeback && conn->capable & FUSE_CAP_WRITEBACK_CACHE) {
		if (scalar->debug)
			fprintf(stderr, "scalar_init: activating writeback\n");
		conn->want |= FUSE_CAP_WRITEBACK_CACHE;
	}
	if (scalar->flock && conn->capable & FUSE_CAP_FLOCK_LOCKS) {
		if (scalar->debug)
			fprintf(stderr, "scalar_init: activating flock locks\n");
		conn->want |= FUSE_CAP_FLOCK_LOCKS;
	}
}

// Get file attributes
static void scalar_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
	struct scalar_data *scalar = scalar_data(req);
	(void) fi;
	struct stat buf;
	int res = fstatat(scalar_fd(req, ino), "", &buf, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return (void) fuse_reply_err(req, errno);
	fuse_reply_attr(req, &buf, scalar->timeout);
}

static int utimensat_empty_nofollow(struct scalar_inode *inode, const struct timespec *tv) {
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
	struct scalar_inode *inode = scalar_inode(req, ino);
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

	ino_t sys_ino = scalar_inode(req, ino)->ino;

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
static struct scalar_inode *scalar_find(struct scalar_data *scalar, struct stat *st) {
	struct scalar_inode *p;
	struct scalar_inode *ret = NULL;
	pthread_mutex_lock(&scalar->mutex);
	for (p = scalar->root.next; p != &scalar->root; p = p->next) {
		if (p->ino == st->st_ino && p->dev == st->st_dev) {
			assert(p->refcount > 0);
			ret = p;
			ret->refcount++;
			break;
		}
	}
	pthread_mutex_unlock(&scalar->mutex);
	return ret;
}

// Look up an inode by name and add it to the linked list of inodes (if its not already present)
// Sets the attributes in e
static int scalar_do_lookup(fuse_req_t req, fuse_ino_t parent, const char *name, struct fuse_entry_param *e) {
	int newfd;
	int res;
	int saverr;
	struct scalar_data *scalar = scalar_data(req);
	struct scalar_inode *inode;
	memset(e, 0, sizeof(*e));
	e->attr_timeout = scalar->timeout;
	e->entry_timeout = scalar->timeout;
	newfd = openat(scalar_fd(req, parent), name, O_PATH | O_NOFOLLOW); // Get file descriptor for file name
	if (newfd == -1)
		goto out_err;
	res = fstatat(newfd, "", &e->attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW); // Get attributes for opened file
	if (res == -1)
		goto out_err;
	inode = scalar_find(scalar_data(req), &e->attr); // Find if inode exists in linked list
	if (inode) {
		// Inode already exists in the linked list
		close(newfd);
		newfd = -1;
	} else {
		// Create new inode entry from file attributes
		struct scalar_inode *prev, *next;
		saverr = ENOMEM;
		inode = calloc(1, sizeof(struct scalar_inode));
		if (!inode)
			goto out_err;
		inode->is_symlink = S_ISLNK(e->attr.st_mode);
		inode->refcount = 1;
		inode->fd = newfd;
		inode->ino = e->attr.st_ino;
		inode->dev = e->attr.st_dev;
		pthread_mutex_lock(&scalar->mutex);
		prev = &scalar->root;
		next = prev->next;
		next->prev = inode;
		inode->next = next;
		inode->prev = prev;
		prev->next = inode;
		pthread_mutex_unlock(&scalar->mutex);
	}
	e->ino = (uintptr_t) inode;
	if (scalar_debug(req))
		fprintf(stderr, "  %lli/%s -> %lli\n", (unsigned long long) parent, name, (unsigned long long) e->ino);
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
	if (scalar_debug(req))
		fprintf(stderr, "scalar_lookup(parent=%" PRIu64 ", name=%s)\n", parent, name);

	err = scalar_do_lookup(req, parent, name, &e); // Populates e with attributes
	if (err)
		fuse_reply_err(req, err);
	else {
		ino_t parent_sys_ino = scalar_inode(req, parent)->ino;
		log_lookup(parent_sys_ino, name, e.attr.st_ino);
		fuse_reply_entry(req, &e);
	}
}

// Helper function to encapsulate similar functionality of mknod, mkdir, and symlink into one function
static void scalar_mknod_symlink(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev, const char *link) {
	int newfd = -1;
	int res;
	int saverr;
	struct scalar_inode *dir = scalar_inode(req, parent);
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
	ino_t parent_sys_ino = scalar_inode(req, parent)->ino;
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
static int linkat_empty_nofollow(struct scalar_inode *inode, int dfd, const char *name) {
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
	struct scalar_data *scalar = scalar_data(req);
	struct scalar_inode *inode = scalar_inode(req, ino);
	struct fuse_entry_param e;
	int saverr;
	memset(&e, 0, sizeof(struct fuse_entry_param));
	e.attr_timeout = scalar->timeout;
	e.entry_timeout = scalar->timeout;

	res = linkat_empty_nofollow(inode, scalar_fd(req, parent), name); // Create the hardlink
	if (res == -1)
		goto out_err;

	res = fstatat(inode->fd, "", &e.attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW); // Get attributes
	if (res == -1)
		goto out_err;

	pthread_mutex_lock(&scalar->mutex);
	inode->refcount++;
	pthread_mutex_unlock(&scalar->mutex);
	e.ino = (uintptr_t) inode;

	ino_t parent_sys_ino = scalar_inode(req, parent)->ino;
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
		ino_t parent_sys_ino = scalar_inode(req, parent)->ino;
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
		ino_t parent_sys_ino = scalar_inode(req, parent)->ino;
		ino_t new_parent_sys_ino = scalar_inode(req, newparent)->ino;
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
		ino_t parent_sys_ino = scalar_inode(req, parent)->ino;

		log_unlink(parent_sys_ino, e.attr.st_ino, name, content);
		fuse_reply_err(req, 0);
        return;
	}
	
out_err:
    fuse_reply_err(req, errno);
}

// Remove 'n' references to an inode
static void unref_inode(struct scalar_data *scalar, struct scalar_inode *inode, uint64_t n) {
	if (!inode) return;
	pthread_mutex_lock(&scalar->mutex);
	assert(inode->refcount >= n);
	inode->refcount -= n;
	if (!inode->refcount) {
		// It is recommended to defer removal of the inode until the lookup count reaches zero
		struct scalar_inode *prev, *next;
		prev = inode->prev;
		next = inode->next;
		next->prev = prev;
		prev->next = next;
		pthread_mutex_unlock(&scalar->mutex);
		close(inode->fd);
		free(inode);
	} else {
		pthread_mutex_unlock(&scalar->mutex);
	}
}

// Forget references to a single inode
static void scalar_forget_one(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
	struct scalar_data *scalar = scalar_data(req);
	struct scalar_inode *inode = scalar_inode(req, ino);
	if (scalar_debug(req)) { 
		fprintf(stderr, "  forget %lli %lli -%lli\n", (unsigned long long) ino, (unsigned long long) inode->refcount, (unsigned long long) nlookup);
	}
	unref_inode(scalar, inode, nlookup);
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
	struct scalar_data *scalar = scalar_data(req);
	struct scalar_dirp *d = calloc(1, sizeof(struct scalar_dirp));
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
	if (scalar->cache == CACHE_ALWAYS)
		fi->keep_cache = 1;
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
	struct scalar_dirp *d = scalar_dirp(fi);
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
				e = (struct fuse_entry_param) {
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
			struct stat st = {
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
	struct scalar_dirp *d = scalar_dirp(fi);
	(void) ino;
	closedir(d->dp);
	free(d);
	fuse_reply_err(req, 0);
}

// Create and open a file
// If the file does not exist, first create it with the specified mode, and then open it.
static void scalar_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi) {
	int fd;
	struct scalar_data *scalar = scalar_data(req);
	struct fuse_entry_param e;
	int err;
	if (scalar_debug(req))
		fprintf(stderr, "scalar_create(parent=%" PRIu64 ", name=%s)\n", parent, name);

	// Test for file existence (to log only creates)
	int not_exists = faccessat(scalar_fd(req, parent), name, F_OK, AT_EACCESS | AT_SYMLINK_NOFOLLOW);

	// Open/create file
	fd = openat(scalar_fd(req, parent), name, (fi->flags | O_CREAT) & ~O_NOFOLLOW, mode);
	if (fd == -1)
		return (void) fuse_reply_err(req, errno);
	fi->fh = fd;
	if (scalar->cache == CACHE_NEVER)
		fi->direct_io = 1;
	else if (scalar->cache == CACHE_ALWAYS)
		fi->keep_cache = 1;
	err = scalar_do_lookup(req, parent, name, &e);

	if (err)
		fuse_reply_err(req, err);
	else {
		// Log file creation
		if(not_exists) {
			ino_t parent_sys_ino = scalar_inode(req, parent)->ino;
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
	int fd = dirfd(scalar_dirp(fi)->dp);
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
	struct scalar_data *scalar = scalar_data(req);
	if (scalar_debug(req))
		fprintf(stderr, "scalar_open(ino=%" PRIu64 ", flags=%d)\n", ino, fi->flags);

	/* With writeback cache, kernel may send read requests even
	   when userspace opened write-only */
	if (scalar->writeback && (fi->flags & O_ACCMODE) == O_WRONLY) {
		fi->flags &= ~O_ACCMODE;
		fi->flags |= O_RDWR;
	}

	/* With writeback cache, O_APPEND is handled by the kernel.
	   This breaks atomicity (since the file may change in the
	   underlying filesystem, so that the kernel's idea of the
	   end of the file isn't accurate anymore). In this example,
	   we just accept that. A more rigorous filesystem may want
	   to return an error here */
	if (scalar->writeback && (fi->flags & O_APPEND))
			fi->flags &= ~O_APPEND;
	sprintf(buf, "/proc/self/fd/%i", scalar_fd(req, ino));
	fd = open(buf, fi->flags & ~O_NOFOLLOW);
	if (fd == -1)
		return (void) fuse_reply_err(req, errno);
	fi->fh = fd;
	if (scalar->cache == CACHE_NEVER)
		fi->direct_io = 1;
	else if (scalar->cache == CACHE_ALWAYS)
		fi->keep_cache = 1;
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
	if (scalar_debug(req))
			fprintf(stderr, "scalar_read(ino=%" PRIu64 ", size=%zd, ""off=%lu)\n", ino, size, (unsigned long) offset);
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
	if (scalar_debug(req))
		fprintf(stderr, "scalar_write(ino=%" PRIu64 ", size=%zd, off=%lu)\n", ino, out_buf.buf[0].size, (unsigned long) off);

	// Log write
	ino_t sys_ino = scalar_inode(req, ino)->ino;
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
		ino_t sys_ino = scalar_inode(req, ino)->ino;
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
	struct scalar_inode *inode = scalar_inode(req, ino);
	ssize_t ret;
	int saverr;
	saverr = ENOSYS;
	if (!scalar_data(req)->xattr)
		goto out;
	if (scalar_debug(req)) {
		fprintf(stderr, "scalar_getxattr(ino=%" PRIu64 ", name=%s size=%zd)\n", ino, name, size);
	}
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
	struct scalar_inode *inode = scalar_inode(req, ino);
	ssize_t ret;
	int saverr;
	saverr = ENOSYS;
	if (!scalar_data(req)->xattr)
		goto out;
	if (scalar_debug(req)) {
		fprintf(stderr, "scalar_listxattr(ino=%" PRIu64 ", size=%zd)\n", ino, size);
	}
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
	struct scalar_inode *inode = scalar_inode(req, ino);
	ssize_t ret;
	int saverr;
	saverr = ENOSYS;
	if (!scalar_data(req)->xattr)
		goto out;
	if (scalar_debug(req)) {
		fprintf(stderr, "scalar_setxattr(ino=%" PRIu64 ", name=%s value=%s size=%zd)\n", ino, name, value, size);
	}
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
		ino_t sys_ino = scalar_inode(req, ino)->ino;
		log_setxattr(sys_ino, name, old_value, value);
	}
	free(old_value);

out:
	fuse_reply_err(req, saverr);
}

// Remove an extended attribute
static void scalar_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name) {
	char procname[64];
	struct scalar_inode *inode = scalar_inode(req, ino);
	ssize_t ret;
	int saverr;
	saverr = ENOSYS;
	if (!scalar_data(req)->xattr)
		goto out;

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
		ino_t sys_ino = scalar_inode(req, ino)->ino;
		log_removexattr(sys_ino, name, old_value);
	}
	free(old_value);

out:
	fuse_reply_err(req, saverr);
}

int main(int argc, char *argv[]) {
	assert(sizeof(fuse_ino_t) >= sizeof(uintptr_t));
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_cmdline_opts opts;
	struct scalar_data scalar = { .debug = 0, .writeback = 0, .xattr = 1 };
	int ret = -1;

	/* Don't mask creation mode, kernel already did that */
	umask(0);
	pthread_mutex_init(&scalar.mutex, NULL);
	scalar.root.next = scalar.root.prev = &scalar.root;
	scalar.root.fd = -1;
	scalar.cache = CACHE_NEVER;

	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;

	if (opts.show_help) {
		printf("usage: %s [options] <mountpoint>\n\n", argv[0]);
		fuse_cmdline_help();
		fuse_lowlevel_help();
		ret = 0;
		goto err_out1;
	} else if (opts.show_version) {
		printf("FUSE library version %s\n", fuse_pkgversion());
		fuse_lowlevel_version();
		ret = 0;
		goto err_out1;
	}

	if(opts.mountpoint == NULL) {
		printf("usage: %s [options] <mountpoint>\n", argv[0]);
		printf("	   %s --help\n", argv[0]);
		ret = 1;
		goto err_out1;
	}

	if (fuse_opt_parse(&args, &scalar, scalar_opts, NULL)== -1)
			return 1;

	scalar.debug = opts.debug;
	scalar.root.refcount = 2;
	if (scalar.source) {
		struct stat stat;
		int res;
		res = lstat(scalar.source, &stat);
		if (res == -1)
			 err(1, "failed to stat source (\"%s\")", scalar.source);
		if (!S_ISDIR(stat.st_mode))
			errx(1, "source is not a directory");
	} else {
		scalar.source = "/";
	}

	scalar.root.is_symlink = false;
	if (!scalar.timeout_set) {
		switch (scalar.cache) {
		case CACHE_NEVER:
			scalar.timeout = 0.0;
			break;
		case CACHE_NORMAL:
			scalar.timeout = 1.0;
			break;
		case CACHE_ALWAYS:
			scalar.timeout = 86400.0;
			break;
		}
	} else if (scalar.timeout < 0) {
		errx(1, "timeout is negative (%lf)", scalar.timeout);
	}

	scalar.root.fd = open(scalar.source, O_PATH);
	if (scalar.root.fd == -1)
			err(1, "open(\"%s\", O_PATH)", scalar.source);

	se = fuse_session_new(&args, &scalar_oper, sizeof(scalar_oper), &scalar);

	if (se == NULL)
		goto err_out1;
	if (fuse_set_signal_handlers(se) != 0)
		goto err_out2;
	if (fuse_session_mount(se, opts.mountpoint) != 0)
		goto err_out3;

	fuse_daemonize(opts.foreground);

	printf("SCALAR started\n");
	if (opts.singlethread)
		ret = fuse_session_loop(se);
	else
		ret = fuse_session_loop_mt(se, opts.clone_fd);

	fuse_session_unmount(se);
err_out3:
	fuse_remove_signal_handlers(se);
err_out2:
	fuse_session_destroy(se);
err_out1:
	free(opts.mountpoint);
	fuse_opt_free_args(&args);
	if (scalar.root.fd >= 0)
		close(scalar.root.fd);
	return ret ? 1 : 0;
}