CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lssl -lcrypto

SRCS = openssl_example.c
OBJS = $(SRCS:.c=.o)
EXEC = example

.PHONY: all clean

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(EXEC)
