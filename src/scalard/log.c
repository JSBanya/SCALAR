#include "log.h"

void print_hex(const char *string) {
	unsigned char *p = (unsigned char *) string;
	for (size_t i = 0; i < strlen(string); i++) {
	    printf("0x%02x ", p[i]);
	}
	fflush(stdout);
}

void log_write_buf(ino_t ino, struct fuse_bufvec *in_buf, off_t off) {
	int content_size = fuse_buf_size(in_buf);
    char *content = (char*) malloc(content_size+1);
    memcpy(content, in_buf->buf[0].mem, content_size);
    content[content_size] = '\0';
    printf("WRITE || ino=%" PRIu64 ", size=%d, pos=%lu, content=%s\n", ino, content_size, (unsigned long) off, content);
    free(content);
    content = 0;
    in_buf->buf[0].pos = off;
}

void log_create(ino_t parent, const char *name, ino_t ino) {
	printf("CREATE || parent_ino=%" PRIu64 ", name=%s, ino=%" PRIu64 "\n", parent, name, ino);
}

void log_rename(ino_t parent, const char *name, ino_t newparent, const char *newname, ino_t ino) {
	printf("RENAME || parent_ino=%" PRIu64 ", new_parent_ino=%" PRIu64 ", ino=%" PRIu64 ", rename=%s -> %s\n", parent, newparent, ino, name, newname);
}

void log_unlink(ino_t parent, ino_t ino, const char *name, char *content) {
	printf("UNLINK || parent_ino=%" PRIu64 ", ino=%" PRIu64 ", name=%s, content=%s\n", parent, ino, name, content);	
}

void log_rmdir(ino_t parent, const char *name) {
	printf("RMDIR || parent_ino=%" PRIu64 ", name=%s\n", parent, name);	
}

void log_mkdir(ino_t parent, const char *name, ino_t ino) {
	printf("MKDIR || parent_ino=%" PRIu64 ", name=%s, ino=%" PRIu64 "\n", parent, name, ino);
}

void log_symlink(ino_t parent, const char *name, ino_t ino, const char *link, ino_t link_ino) {
	printf("SYMLINK || parent_ino=%" PRIu64 ", name=%s, ino=%" PRIu64 ", link=%s, link_ino=%" PRIu64 "\n", parent, name, ino, link, link_ino);
}

void log_mknod(ino_t parent, const char *name) {
	printf("MKNOD || parent_ino=%" PRIu64 ", name=%s\n", parent, name);
}

void log_lookup(ino_t parent, const char *name, ino_t ino) {
	printf("LOOKUP || parent_ino=%" PRIu64 ", name=%s, ino=%" PRIu64 "\n", parent, name, ino);
}

void log_link(ino_t parent, const char *name, ino_t ino) {
	printf("HARDLINK || parent_ino=%" PRIu64 ", name=%s, ino=%" PRIu64 "\n", parent, name, ino);
}

void log_fallocate(ino_t ino, off_t size_before, off_t offset, off_t length) {
	printf("FALLOCATE || ino=%" PRIu64 ", size_before=%ld, offset=%ld, length=%ld\n", ino, size_before, offset, length);
}

void log_setxattr(ino_t ino, const char *name, char *old_value, const char *value) {
	printf("SETXATTR || ino=%" PRIu64 ", name=%s, old_value=%s, value=%s\n", ino, name, old_value, value);
}

void log_removexattr(ino_t ino, const char *name, char *old_value) {
	printf("REMOVEXATTR || ino=%" PRIu64 ", name=%s, old_value=%s\n", ino, name, old_value);
}

/******************
* setattr functions
*******************/
void log_setattr_chmod(ino_t ino, struct stat *before, struct stat *after) {
	printf("SETATTR CHMOD || ino=%" PRIu64 ", mode: %d -> %d\n", ino, before->st_mode, after->st_mode);
}

void log_setattr_uid_or_gid(ino_t ino, struct stat *before, struct stat *after) {
	printf("SETATTR UID-GID || ino=%" PRIu64 ", uid: %d -> %d, gid: %d -> %d\n", ino, before->st_uid, after->st_uid, before->st_gid, after->st_gid);
}

void log_setattr_truncate(ino_t ino, off_t size_before, off_t size_after, char* data_lost) {
	printf("SETATTR TRUNCATE || ino=%" PRIu64 ", size: %ld -> %ld, data_lost: %s\n", ino, size_before, size_after, data_lost);
}
