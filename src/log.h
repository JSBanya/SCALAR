#ifndef SCALAR_LOG_H
#define SCALAR_LOG_H

#define _GNU_SOURCE
#define FUSE_USE_VERSION 31
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

void print_hex(const char *string);
void log_write_buf(ino_t ino, struct fuse_bufvec *in_buf, off_t off);
void log_create(ino_t parent, const char *name, ino_t ino);
void log_rename(ino_t parent, const char *name, ino_t newparent, const char *newname, ino_t ino);
void log_unlink(ino_t parent, const char *name);
void log_rmdir(ino_t parent, const char *name);
void log_mkdir(ino_t parent, const char *name, ino_t ino);
void log_symlink(ino_t parent, const char *name, ino_t ino, const char *link, ino_t link_ino);
void log_mknod(ino_t parent, const char *name);

void log_lookup(ino_t parent, const char *name, ino_t ino);

// ino_t parent_sys_ino = scalar_inode(req, parent)->ino;

#endif