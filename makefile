mcp_files=src/mcp/*.c
includes=-Iinclude/
CFLAGS=-Wall

all: mcp

mcp: $(mcp_files) test.c
	$(CC) $(CFLAGS) $(includes) $^ -o $@