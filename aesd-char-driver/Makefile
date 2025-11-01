# See example Makefile from scull project
# Comment/uncomment the following line to disable/enable debugging
#DEBUG = y

# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  DEBFLAGS = -O -g -DAESD_DEBUG # "-O" is needed to expand inlines
else
  DEBFLAGS = -O2
endif

EXTRA_CFLAGS += $(DEBFLAGS)

# ifneq ($(KERNELRELEASE),)
# call from kernel build system
obj-m	:= aesdchar.o
aesdchar-y := aesd-circular-buffer.o main.o
# else
# KERNELDIR ?= /lib/modules/$(shell uname -r)/build	# buildroot
#KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build	# Yocto

PWD := $(shell pwd)

all:
	# $(MAKE) -C $(KERNELDIR) M=$(PWD) modules	# Buildroot
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD)	# Yocto

modules_install:
	# $(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install	# Buildroot
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules_install	# Yocto
#endif

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers

