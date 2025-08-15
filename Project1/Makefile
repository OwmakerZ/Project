CC = gcc
CFLAGS = -Wall -O2
TARGET = sm4_test

SRC_BASIC = sm4.c
SRC_TTABLE = ttable.c
SRC_AESNI = aesni.c ttable.c
SRC_GCM = sm4.c gcm.c
SRC_MAIN = main.c

# 选择优化版本：BASIC / TTABLE / AESNI
VERSION ?= BASIC

ifeq ($(VERSION),BASIC)
    SRC_OPT = $(SRC_BASIC)
    CFLAGS += -DUSE_BASIC
endif

ifeq ($(VERSION),TTABLE)
    SRC_OPT = $(SRC_TTABLE)
    CFLAGS += -DUSE_TTABLE
endif

ifeq ($(VERSION),AESNI)
    SRC_OPT = $(SRC_AESNI)
    CFLAGS += -DUSE_AESNI -maes
endif

# 默认启用 GCM
CFLAGS += -DUSE_GCM
SRC_ALL = $(SRC_OPT) $(SRC_GCM) $(SRC_MAIN)

all:
	$(CC) $(CFLAGS) $(SRC_ALL) -o $(TARGET)

launch:
	.\sm4_test.exe

clean:
	rm -f $(TARGET)
