CC = gcc
CFLAGS = -Wall -Wextra -Werror -pthread -O2 -g -D_POSIX_C_SOURCE=200809L
LDFLAGS = -pthread

SRCS = main.c \
       proxy.c \
       thread_pool.c \
       http_handler.c \
       logger.c \
       picohttpparser.c \
       cache.c

HEADERS = proxy.h \
          thread_pool.h \
          http_handler.h \
          logger.h \
          picohttpparser.h \
          cache.h

OBJS = $(SRCS:.c=.o)
TARGET = http_proxy

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)