#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <uv.h>
#include "mcp.h"

typedef struct {
	int state;
	uv_tcp_t tcp;
	uv_connect_t connect_req;
	uv_shudown_t shutdown_req;
} client_t;

static mcp_hs00_t handshake = {
	.protocol_version = 5,
	.addr_len         = strlen("127.0.0.1"),
	.server_addr      = "127.0.0.1",
	.server_port      = 25565,
	.next_state       = 2
};

void client_write_handshake(client_t *client) {
	uv_write_t *req;
	uv_buf_t buf;
	uint8_t pbuf[4096];
}

void client_connect_cb(uv_connect_t *req, int status) {

}

int main(int argc, char *argv[]) {
	struct sockaddr_in server_addr;
	uv_loop_t *loop = uv_default_loop();
	client_t myclient;
	uv_ip4_addr("127.0.0.1", 25565, &server_addr);
	uv_tcp_init(loop, &myclient.tcp);
	myclient.state = 0;
	myclient.tcp.data = &myclient;
	uv_tcp_connect(
		&myclient.connect_req, 
		&myclient.tcp,
		(struct sockaddr*) &server_addr,
		client_connect_cb
	);
	return uv_run(loop, UV_RUN_DEFAULT);
}
