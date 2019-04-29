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
void log_write_buf(fuse_ino_t ino, struct fuse_bufvec *in_buf, off_t off);
void log_create(fuse_ino_t parent, const char *name, fuse_ino_t ino);
void log_rename(fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname, fuse_ino_t ino);
void log_unlink(fuse_ino_t parent, const char *name);
void log_rmdir(fuse_ino_t parent, const char *name);
void log_mkdir(fuse_ino_t parent, const char *name, fuse_ino_t ino);
void log_symlink(fuse_ino_t parent, const char *name, fuse_ino_t ino, const char *link, fuse_ino_t link_ino);
void log_mknod(fuse_ino_t parent, const char *name);

#endif