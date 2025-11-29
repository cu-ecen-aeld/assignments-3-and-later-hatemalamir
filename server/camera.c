/*
 *  V4L2 video capture example
 *
 *  This program can be used and distributed without restrictions.
 *
 *      This program is provided with the V4L2 API
 * see https://linuxtv.org/docs.php for more information
 *
 * Modfied by Hatem Alamir
 */
#include "camera.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <getopt.h> 

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include <linux/videodev2.h>

#define CAMERA_CLEAR(x) memset(&(x), 0, sizeof(x))

static void print_err(const char *s, struct camera *context, int pr_errno) {
	if(pr_errno)
		syslog(LOG_ERR, "%s error %d, %s, on device %s\n", s, errno, strerror(errno),
				context->dev_name);
	else
		syslog(LOG_ERR, "%s. Device %s\n", s, context->dev_name);
}

static int xioctl(int fh, int request, void *arg) {
	int r;
	do {
		r = ioctl(fh, request, arg);
	} while (-1 == r && EINTR == errno);

	return r;
}

int read_frame(struct camera *context, void *out_buf) {
	struct v4l2_buffer buf;
	unsigned int i;

	switch (context->io) {
	case IO_METHOD_READ:
		if (-1 == read(context->fd, context->buffers[0].start, context->buffers[0].length)) {
			switch (errno) {
			case EAGAIN:
				return 0;
			case EIO:
				/* Could ignore EIO, see spec. */
				/* fall through */
			default:
				print_err("read_frame: read", context, 1);
				return -1;
			}
		}
		memcpy(out_buf, context->buffers[0].start, context->buffers[0].length);
		break;

	case IO_METHOD_MMAP:
		CAMERA_CLEAR(buf);
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;

		if (-1 == xioctl(context->fd, VIDIOC_DQBUF, &buf)) {
			switch (errno) {
			case EAGAIN:
				return 0;
			case EIO:
				/* Could ignore EIO, see spec. */
				/* fall through */
			default:
				print_err("read_frame: VIDIOC_DQBUF", context, 1);
				return -1;
			}
		}

		if(buf.index >= context->n_buffers) {
			char *msg;
			asprintf(&msg, "Incorrect buf index %u", buf.index);
			print_err(msg, context, 0);
			free(msg);
			return -1;
		}
		memcpy(out_buf, context->buffers[buf.index].start, buf.bytesused);

		if (-1 == xioctl(context->fd, VIDIOC_QBUF, &buf)) {
			print_err("VIDIOC_QBUF", context, 1);
			return -1;
		}
		break;

	case IO_METHOD_USERPTR:
		CAMERA_CLEAR(buf);
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_USERPTR;
		if (-1 == xioctl(context->fd, VIDIOC_DQBUF, &buf)) {
			switch (errno) {
			case EAGAIN:
				return 0;
			case EIO:
				/* Could ignore EIO, see spec. */
				/* fall through */
			default:
				print_err("VIDIOC_DQBUF", context, 1);
				return -1;
			}
		}

		for (i = 0; i < context->n_buffers; ++i)
			if (buf.m.userptr == (unsigned long)(context->buffers[i].start) && buf.length == context->buffers[i].length)
				break;
		if(i >= context->n_buffers) {
			print_err("No buffer found matching usrptr", context, 0);
			return -1;
		}
		memcpy(out_buf, (void *)buf.m.userptr, buf.bytesused);

		if (-1 == xioctl(context->fd, VIDIOC_QBUF, &buf)) {
			print_err("VIDIOC_QBUF", context, 1);
			return -1;
		}
		break;
	}

	syslog(LOG_DEBUG, "Read 1 frame from %s", context->dev_name);
	return 1;
}

static int stop_capturing(struct camera *context) {
	enum v4l2_buf_type type;
	switch (context->io) {
	case IO_METHOD_READ:
		/* Nothing to do. */
		break;

	case IO_METHOD_MMAP:
	case IO_METHOD_USERPTR:
		type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		if (-1 == xioctl(context->fd, VIDIOC_STREAMOFF, &type)) {
			print_err("VIDIOC_STREAMOFF", context, 1);
			return -1;
		}
		break;
	}

	syslog(LOG_DEBUG, "Stopped capturing frames from %s", context->dev_name);
	return 0;
}

static int start_capturing(struct camera *context) {
	unsigned int i;
	enum v4l2_buf_type type;

	switch (context->io) {
	case IO_METHOD_READ:
		/* Nothing to do. */
		break;

	case IO_METHOD_MMAP:
		for (i = 0; i < context->n_buffers; ++i) {
			struct v4l2_buffer buf;
			CAMERA_CLEAR(buf);
			buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
			buf.memory = V4L2_MEMORY_MMAP;
			buf.index = i;

			if (-1 == xioctl(context->fd, VIDIOC_QBUF, &buf)) {
				print_err("VIDIOC_QBUF", context, 1);
				return -1;
			}
		}
		type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		if (-1 == xioctl(context->fd, VIDIOC_STREAMON, &type)) {
			print_err("VIDIOC_STREAMON", context, 1);
			return -1;
		}
		break;

	case IO_METHOD_USERPTR:
		for (i = 0; i < context->n_buffers; ++i) {
			struct v4l2_buffer buf;
			CAMERA_CLEAR(buf);
			buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
			buf.memory = V4L2_MEMORY_USERPTR;
			buf.index = i;
			buf.m.userptr = (unsigned long)(context->buffers[i].start);
			buf.length = context->buffers[i].length;
			if (-1 == xioctl(context->fd, VIDIOC_QBUF, &buf)) {
				print_err("VIDIOC_QBUF", context, 1);
				return -1;
			}
		}
		type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		if (-1 == xioctl(context->fd, VIDIOC_STREAMON, &type)) {
			print_err("VIDIOC_STREAMON", context, 1);
			return -1;
		}
		break;
	}

	syslog(LOG_DEBUG, "Started capturing frames from %s", context->dev_name);
	return 0;
}

static void uninit_device(struct camera *context) {
	if(!context->buffers)
		return;

	unsigned int i;
	switch (context->io) {
	case IO_METHOD_MMAP:
		for (i = 0; i < context->n_buffers; ++i) {
			if (-1 == munmap(context->buffers[i].start, context->buffers[i].length))
				print_err("munmap", context, 1);
			context->buffers[i].start = NULL;
			context->buffers[i].length = 0;
		}
		break;

	case IO_METHOD_READ:
	case IO_METHOD_USERPTR:
		for (i = 0; i < context->n_buffers; ++i) {
			free(context->buffers[i].start);
			context->buffers[i].start = NULL;
			context->buffers[i].length = 0;
		}
		break;
	}

	free(context->buffers);
	context->buffers = NULL;

	syslog(LOG_DEBUG, "Uninitialized device %s", context->dev_name);
}

static int init_read(unsigned int buffer_size, struct camera *context)
{
	context->buffers = calloc(1, sizeof(*context->buffers));

	if (!context->buffers) {
		print_err("Out of memory", context, 0);
		return -1;
	}

	context->buffers[0].length = buffer_size;
	context->buffers[0].start = malloc(buffer_size);

	if (!context->buffers[0].start) {
		print_err("Out of memory", context, 0);
		return -1;
	}
	context->n_buffers = 1;

	syslog(LOG_DEBUG, "Initiated read system calls on device %s", context->dev_name);
	return 0;
}

static int init_mmap(struct camera *context) {
	struct v4l2_requestbuffers req;
	CAMERA_CLEAR(req);

	req.count = 4;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	req.memory = V4L2_MEMORY_MMAP;

	if (-1 == xioctl(context->fd, VIDIOC_REQBUFS, &req)) {
		if (EINVAL == errno) {
			print_err("Device does not support memory mapping", context, 0);
			return -1;
		} else {
			print_err("VIDIOC_REQBUFS", context, 1);
			return -1;
		}
	}

	if (req.count < 2) {
		print_err("Insufficient buffer memory", context, 0);
		return -1;
	}

	context->buffers = calloc(req.count, sizeof(*context->buffers));

	if (!context->buffers) {
		print_err("Out of memory", context, 0);
		return -1;
	}

	for (context->n_buffers = 0; context->n_buffers < req.count; ++(context->n_buffers)) {
		struct v4l2_buffer buf;
		CAMERA_CLEAR(buf);
		buf.type        = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory      = V4L2_MEMORY_MMAP;
		buf.index       = context->n_buffers;

		if (-1 == xioctl(context->fd, VIDIOC_QUERYBUF, &buf)) {
			print_err("VIDIOC_QUERYBUF", context, 1);
			return -1;
		}

		context->buffers[context->n_buffers].length = buf.length;
		context->buffers[context->n_buffers].start = mmap(NULL /* start anywhere */,
				buf.length,
				PROT_READ | PROT_WRITE /* required */,
				MAP_SHARED /* recommended */,
				context->fd, buf.m.offset);

		if (MAP_FAILED == context->buffers[context->n_buffers].start) {
			print_err("mmap failed", context, 0);
			return -1;
		}
	}
 
	syslog(LOG_DEBUG, "Initialized mmap on device %s", context->dev_name);
	return 0;
}

static int init_userp(unsigned int buffer_size, struct camera *context) {
	struct v4l2_requestbuffers req;
	CAMERA_CLEAR(req);
	req.count  = 4;
	req.type   = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	req.memory = V4L2_MEMORY_USERPTR;

	if (-1 == xioctl(context->fd, VIDIOC_REQBUFS, &req)) {
		if (EINVAL == errno) {
			print_err("Device does not support user pointer i/o", context, 0);
			return -1;
		} else {
			print_err("VIDIOC_REQBUFS", context, 1);
			return -1;
		}
	}

	context->buffers = calloc(4, sizeof(*context->buffers));

	if (!context->buffers) {
		print_err("Out of memory", context, 0);
		return -1;
	}

	for (context->n_buffers = 0; context->n_buffers < 4; ++(context->n_buffers)) {
		context->buffers[context->n_buffers].length = buffer_size;
		context->buffers[context->n_buffers].start = malloc(buffer_size);

		if (!context->buffers[context->n_buffers].start) {
			print_err("Out of memory", context, 0);
			return -1;
		}
	}

	syslog(LOG_DEBUG, "Initialized userp on device %s", context->dev_name);
	return 0;
}

static int init_device(struct camera *context) {
	struct v4l2_capability cap;
	if (-1 == xioctl(context->fd, VIDIOC_QUERYCAP, &cap)) {
		if (EINVAL == errno)
			print_err("Device is no V4L2", context, 0);
		else
			print_err("VIDIOC_QUERYCAP", context, 1);
		return -1;
	}

	if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE)) {
		print_err("Device is no video capture device", context, 0);
		return -1;
	}

	switch (context->io) {
	case IO_METHOD_READ:
		if (!(cap.capabilities & V4L2_CAP_READWRITE)) {
			print_err("Device does not support read i/o", context, 0);
			return -1;
		}
		break;

	case IO_METHOD_MMAP:
	case IO_METHOD_USERPTR:
		if (!(cap.capabilities & V4L2_CAP_STREAMING)) {
			print_err("Device does not support streaming i/o", context, 0);
			return -1;
		}
		break;
	}

	/* Select video input, video standard and tune here. */

	struct v4l2_cropcap cropcap;
	CAMERA_CLEAR(cropcap);
	cropcap.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

	struct v4l2_crop crop;
	if (0 == xioctl(context->fd, VIDIOC_CROPCAP, &cropcap)) {
		crop.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		crop.c = cropcap.defrect; /* reset to default */

		if (-1 == xioctl(context->fd, VIDIOC_S_CROP, &crop)) {
			switch (errno) {
			case EINVAL:
				/* Cropping not supported. */
				break;
			default:
				/* Errors ignored. */
				break;
			}
		}
	} else {
		/* Errors ignored. */
	}

	struct v4l2_format fmt;
	CAMERA_CLEAR(fmt);

	fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if (context->force_format) {
		fmt.fmt.pix.width         = context->width;
		fmt.fmt.pix.height        = context->height;
		fmt.fmt.pix.field         = V4L2_FIELD_INTERLACED;
		if(context->format_yuv)
			fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
		else
			fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_MJPEG;

		if (-1 == xioctl(context->fd, VIDIOC_S_FMT, &fmt)) {
			print_err("VIDIOC_S_FMT", context, 1);
			return -1;
		}
		/* Note VIDIOC_S_FMT may change width and height. */
	} else {
		/* Preserve original settings as set by v4l2-ctl for example */
		if (-1 == xioctl(context->fd, VIDIOC_G_FMT, &fmt)) {
			print_err("VIDIOC_G_FMT", context, 1);
			return -1;
		}
	}

	/* Buggy driver paranoia. */
	unsigned int min;
	min = fmt.fmt.pix.width * 2;
	if (fmt.fmt.pix.bytesperline < min)
		fmt.fmt.pix.bytesperline = min;
	min = fmt.fmt.pix.bytesperline * fmt.fmt.pix.height;
	if (fmt.fmt.pix.sizeimage < min)
		fmt.fmt.pix.sizeimage = min;

	context->img_size = fmt.fmt.pix.sizeimage;

	int st;
	switch (context->io) {
	case IO_METHOD_READ:
		st = init_read(fmt.fmt.pix.sizeimage, context);

	case IO_METHOD_MMAP:
		st = init_mmap(context);

	case IO_METHOD_USERPTR:
		st = init_userp(fmt.fmt.pix.sizeimage, context);
	}

	if(st == -1)
		return st;

	syslog(LOG_DEBUG, "Initialized device %s", context->dev_name);
	return 0;
}

static void close_device(struct camera *context) {
	if(-1 == context->fd)
		return;

	if (-1 == close(context->fd))
		print_err("close", context, 1);

	context->fd = -1;

	syslog(LOG_DEBUG, "Closed device %s", context->dev_name);
}

static int open_device(struct camera *context) {
	struct stat st;
	if (-1 == stat(context->dev_name, &st)) {
		print_err("Cannot identify device", context, 1);
		return -1;
	}

	if (!S_ISCHR(st.st_mode)) {
		print_err("Device is no device", context, 0);
		return -1;
	}

	int fd = open(context->dev_name, O_RDWR /* required */ | O_NONBLOCK, 0);

	if (-1 == fd) {
		print_err("Cannot open device", context, 1);
		return -1;
	}
	context->fd = fd;

	syslog(LOG_DEBUG, "Opened device %s", context->dev_name);
	return 0;
}

int init_camera(struct camera *context) {
	if(-1 == open_device(context))
		return -1;
	if(-1 == init_device(context))
		return -1;
	if(-1 == start_capturing(context))
		return -1;

	syslog(LOG_DEBUG, "Initialized camera device %s", context->dev_name);
	return 0;
}

void uninit_camera(struct camera *context) {
	stop_capturing(context);
	uninit_device(context);
	close_device(context);

	syslog(LOG_DEBUG, "Uninitialized camera device %s", context->dev_name);
}
