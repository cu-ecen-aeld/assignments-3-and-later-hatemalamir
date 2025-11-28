#ifndef CAMERA_H
#define CAMERA_H

#include <stdlib.h>

#define CAMERA_DEFAULT_DEV "/dev/video0"
#define CAMERA_DEFAULT_WIDTH 640
#define CAMERA_DEFAULT_HEIGHT 480

enum camera_io_method {
	IO_METHOD_READ,
	IO_METHOD_MMAP,
	IO_METHOD_USERPTR,
};

struct camera_buffer {
	void   *start;
	size_t  length;
};

struct camera {
	char                 *dev_name;
	int                   fd;
	enum camera_io_method io;
	int                   force_format;
	unsigned int          width;
	unsigned int          height;
	int                   format_yuv;
	struct camera_buffer *buffers;
	unsigned int          n_buffers;
	unsigned int          img_size;
};

int init_camera(struct camera *);
void uninit_camera(struct camera *);
int read_frame(struct camera *, void *);

#endif /* CAMERA_H */
