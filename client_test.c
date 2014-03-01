#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uv.h>
#include "mcp.h"

typedef struct {
	uint8_t *base;
	uint8_t *cur;
	size_t len;
	size_t used;
	size_t rem;
} client_buf_t;

typedef struct {
	int state;
	client_buf_t client_buf;
	int32_t read_len;
	uv_tcp_t tcp;
	uv_connect_t connect_req;
	uv_shutdown_t shutdown_req;
} client_t;

static mcp_hs00_t handshake = {
	.protocol_version = 4,
	.addr_len         = sizeof("127.0.0.1")-1,
	.server_addr      = "127.0.0.1",
	.server_port      = 25565,
	.next_state       = 1
};

static mcp_ss00_t ping_req;

client_t* client_init(client_t *client, uint8_t *buf, size_t len)
{
	if((len == 0)||(buf == NULL)) {
		len = 4096;
		buf = malloc(len);
	}
	client->state = 0;
	client->client_buf.base = buf;
	client->client_buf.cur = buf;
	client->client_buf.len = len;
	client->client_buf.used = 0;
	client->client_buf.rem = 0;
	client->read_len = -1;
	client->tcp.data = client;
	return client;
}

void read_buf_alloc(uv_handle_t *tcp, size_t size, uv_buf_t *buf)
{
	client_t *client = (client_t*)tcp->data;
	client_buf_t *client_buf = &client->client_buf;
	if (
		(size > client_buf->len - client_buf->used) &&
		(size <= client_buf->len - client_buf->rem) 
	) {
		memmove(client_buf->base, client_buf->cur, client_buf->rem);
		client_buf->cur = client_buf->base;
		client_buf->used = client_buf->rem;
	} else if (size > client_buf->len - client_buf->rem) {
		size_t s = ((size + client_buf->rem)/client_buf->len)+1;
		s = s*client_buf->len;
		uint8_t *c = memcpy(malloc(s), client_buf->cur, client_buf->rem);
		free(client_buf->base);
		client_buf->base = c;
		client_buf->cur = c;
		client_buf->len = s;
	}

	*buf = uv_buf_init(
		(char*)client_buf->base + client_buf->used, 
		client_buf->len - client_buf->used
	);
}

void client_shutdown_cb(uv_shutdown_t *req, int status)
{
	printf("Shutting down...\n");
}

void client_close_cb(uv_handle_t* handle)
{
	client_t *client = (client_t*)handle->data;
	client_buf_t *client_buf = &client->client_buf;
	free(client_buf->base);
	free(client);
}

void client_write_cb(uv_write_t *req, int status)
{
	free(req->data);
	free(req);
}

void client_write_ss01(client_t *client)
{
	uv_write_t *req;
	uv_buf_t buf;
	uint8_t pbuf[4096];
	mcp_ss01_t p;
	p.ping_time = (int64_t)time(NULL);
	int ret = mcp_encode_ss01(pbuf, &p, 4096);
	buf = uv_buf_init(memcpy(malloc(ret), pbuf, ret), ret);
	req = malloc(sizeof(*req));
	req->data = buf.base;
	uv_write(req, (uv_stream_t*)&client->tcp, &buf, 1, client_write_cb);
	printf("Ping Time Sent: %d\n", (int)p.ping_time);
}

void client_write_hs00(client_t *client)
{
	uv_write_t *req;
	uv_buf_t buf;
	uint8_t pbuf[4096];
	int ret = mcp_encode_hs00(pbuf, &handshake, 4096);
	buf = uv_buf_init(memcpy(malloc(ret), pbuf, ret), ret);
	req = malloc(sizeof(*req));
	req->data = buf.base;
	client->state = 0x02;
	uv_write(req, (uv_stream_t*)&client->tcp, &buf, 1, client_write_cb);
}

void client_write_ss00(client_t *client)
{
	uv_write_t *req;
	uv_buf_t buf;
	uint8_t pbuf[4096];
	int ret = mcp_encode_ss00(pbuf, &ping_req, 4096);
	buf = uv_buf_init(memcpy(malloc(ret), pbuf, ret), ret);
	req = malloc(sizeof(*req));
	req->data = buf.base;
	uv_write(req, (uv_stream_t*)&client->tcp, &buf, 1, client_write_cb);
}

void client_read_cb(uv_stream_t *tcp, ssize_t nread, const uv_buf_t *buf)
{
	client_t *client = (client_t*)tcp->data;
	client_buf_t *client_buf = &client->client_buf;
	int ret;

	if (nread<0) {
		uv_close((uv_handle_t*)tcp, client_close_cb);
		return;
	} else if (nread == 0) {
		return;
	}

	client_buf->used += nread;
	client_buf->rem  += nread;
	for(;;) {
		if (client->read_len < 0) {
			ret = mcp_decode_varint(
				&client->read_len, 
				client_buf->cur,
				client_buf->rem
			);
			if (ret < 0) {
				client->read_len = -1;
				break;
			}
			client_buf->cur += ret;
			client_buf->rem -= ret;
		}
		if (client_buf->rem < client->read_len) {
			break;
		}
	
		int32_t packet_id;
		ret = mcp_decode_varint(
			&packet_id, 
			client_buf->cur,
			client_buf->rem
		);
		client_buf->cur += ret;
		client_buf->rem -= ret;
		switch (client->state) {
			case 0x02: switch(packet_id) {
				case 0x00: ;
					mcp_sc00_t psc00;
					ret = mcp_decode_sc00(&psc00, client_buf->cur,
						client_buf->rem, malloc);
					printf("%.*s\n", (int)psc00.str_len, psc00.str);
					client_write_ss01(client);
					free(psc00.str);
					break;
				case 0x01: ;
					mcp_sc01_t psc01;
					ret = mcp_decode_sc01(&psc01, client_buf->cur, client_buf->rem);
					printf("Ping Time Recieved: %d\n", (int)psc01.ping_time);
					uv_shutdown(
						&client->shutdown_req, 
						(uv_stream_t*)tcp, 
						client_shutdown_cb
					);
					break;
				default:
					printf("%s\n", "Entered P default, something is wrong");
					ret = 0;
					break;
			} break;

			default:
				printf("%s\n", "Entered S default, something is wrong");
				break;
		}
		client_buf->cur += ret;
		client_buf->rem -= ret;
		client->read_len = -1;
	}
}

void client_connect_cb(uv_connect_t *req, int status)
{
	client_t *client = (client_t*)req->handle->data;
	client_write_hs00(client);
	client_write_ss00(client);
	uv_read_start(req->handle, read_buf_alloc, client_read_cb);
}

int main(int argc, char *argv[])
{
	struct sockaddr_in server_addr;
	uv_loop_t *loop = uv_default_loop();
	client_t *myclient = malloc(sizeof(*myclient));
	client_init(myclient, malloc(4096), 4096);
	uv_ip4_addr("127.0.0.1", 25565, &server_addr);
	uv_tcp_init(loop, &myclient->tcp);
	uv_tcp_connect(
		&myclient->connect_req, 
		&myclient->tcp,
		(struct sockaddr*)&server_addr,
		client_connect_cb
	);
	return uv_run(loop, UV_RUN_DEFAULT);
}
