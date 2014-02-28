mcp_files=src/mcp/*.c
includes=-Iinclude/
CFLAGS=-Wall

all: mcp

mcp: $(mcp_files) test.c
	$(CC) $(CFLAGS) $(includes) $^ -o $@

ping_test: $(mcp_files) client_test.c
	$(CC) $(CFLAGS) $(includes) -luv $^ -o $@
