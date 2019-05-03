#include "log.h"

void print_hex(const char *string) {
	unsigned char *p = (unsigned char *) string;
	for (int i = 0; i < strlen(string); i++) {
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

void log_unlink(ino_t parent, const char *name) {
	printf("UNLINK || parent_ino=%" PRIu64 ", name=%s\n", parent, name);	
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