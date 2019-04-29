#include "log.h"

void print_hex(const char *string) {
	unsigned char *p = (unsigned char *) string;
	for (int i = 0; i < strlen(string); i++) {
	    printf("0x%02x ", p[i]);
	}
	fflush(stdout);
}

void log_write_buf(fuse_ino_t ino, struct fuse_bufvec *in_buf, off_t off) {
	int content_size = fuse_buf_size(in_buf);
    char *content = (char*) malloc(content_size+1);
    memcpy(content, in_buf->buf[0].mem, content_size);
    content[content_size] = '\0';
    printf("WRITE || ino=%" PRIu64 ", size=%d, pos=%lu -> %s\n", ino, content_size, (unsigned long) off, content);
    free(content);
    content = 0;
    in_buf->buf[0].pos = off;
}

void log_create(fuse_ino_t parent, const char *name, fuse_ino_t ino) {
	printf("CREATE || parent_ino=%" PRIu64 ", name=%s, ino=%" PRIu64 "\n", parent, name, ino);
}

