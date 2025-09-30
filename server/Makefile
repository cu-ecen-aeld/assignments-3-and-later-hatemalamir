#******************************************************************************
# Copyright (C) 2025 by Hatem Alamir
#
# Redistribution, modification or use of this software in source or binary
# forms is permitted as long as the files maintain this copyright. Users are 
# permitted to modify this and use it to learn about the field of embedded
# software. Hatem Alamir is not liable for any misuse of this material. 
#
#*****************************************************************************

#------------------------------------------------------------------------------
# Main make file for assignment 5 of the Linux System Programming and
# Introduction to Buildroot Coursera course.
# Build aesdsocket
#
# Use: make [TARGET] [CROSS-COMPILE-OVERRIDE]
#
# Build Targets:
#      1) Host machine with GNU GCC.
#      2) Arch64 based embedded computer running Linux.
#
# Cross-compile Override:
#      None - When the CROSS_COMPILE variable is not specified on the the make
#      command line, build for the host machine.
#      aarch64-none-linux-gnu - When the CROSS_COMPILE variable is specified
#      with this value, cross-compile for and Arch64 based embedded processor
#      running Linux.
#
#------------------------------------------------------------------------------
include sources.mk

ifdef CROSS_COMPILE
	CC ?= $(CROSS_COMPILE)gcc
else
	CC ?= gcc
endif

CFLAGS ?= -g -Wall -Werror -O0 -pthread

USE_AESD_CHAR_DEVICE ?= 1
ifneq ($(USE_AESD_CHAR_DEVICE),)
	CFLAGS += -DUSE_AESD_CHAR_DEVICE=$(USE_AESD_CHAR_DEVICE)
endif

OBJ = $(SRC:.c=.o)

TARGET ?= aesdsocket

LDFLAGS ?= -lpthread -lrt

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $(TARGET) $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: all clean

clean:
	rm -f $(OBJ) $(TARGET)
