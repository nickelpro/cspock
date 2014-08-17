mcp_files=src/mcp/*.c
libdir=-Llibuv/lib/
includes=-Iinclude/ -Ilibuv/include/
CFLAGS=-Wall

all: mcp

mcp: $(mcp_files) test.c
	$(CC) $(CFLAGS) $(includes) $^ -o $@

ping_test: $(mcp_files) client_test.c
	$(CC) $(CFLAGS) $(libdir) $(includes) -luv -Wl,-rpath,/home/nick/code/cspock/libuv/lib/ $^ -o $@

server_test: $(mcp_files) src/server/*.c
	$(CC) -g $(CFLAGS) $(libdir) $(includes) -luv -Wl,-rpath,/home/nick/code/cspock/libuv/lib $^ -o $@ 
