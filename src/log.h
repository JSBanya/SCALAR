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

#endif