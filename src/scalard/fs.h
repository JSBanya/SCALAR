#ifndef SCALAR_FS_H__
#define SCALAR_FS_H__

#define SCALAR_MOUNTPOINT "/tmp/scalar_mount"

/* Allocates SCALAR FS data */
struct fs_data *fs_new(void);

/* Activates a SCALAR FS. Returns 0 on success, -1 on failure. */
int fs_activate(struct fs_data *data);

/* Frees SCALAR FS data */
void fs_free(struct fs_data *data);

#endif
