# Makefile
CC = gcc
CFLAGS = -Wall -Wextra -pthread
LDFLAGS = -lssl -lcrypto
SERVER_SRC = server.c
CLIENT_SRC = client.c
SERVER_OUT = server
CLIENT_OUT = client

all: server client

server: $(SERVER_SRC)
	$(CC) $(CFLAGS) $(SERVER_SRC) -o $(SERVER_OUT) $(LDFLAGS)

client: $(CLIENT_SRC)
	$(CC) $(CFLAGS) $(CLIENT_SRC) -o $(CLIENT_OUT) $(LDFLAGS)

clean:
	rm -f $(SERVER_OUT) $(CLIENT_OUT)
