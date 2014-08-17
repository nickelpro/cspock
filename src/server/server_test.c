#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uv.h>
#include "mcp.h"

typedef struct {
	unsigned int num_clients;
	unsigned int max_clients;
	uv_tcp_t tcp;
} server_t;

typedef struct {
	uint8_t *base;//Base of buffer
	uint8_t *cur; //Base of unprocessed data
	size_t len;   //Total length of the buffer
	size_t used;  //Total used length of the buffer
	size_t rem;   //Length of unprocessed data
} client_buf_t;

typedef struct {
	int state;
	client_buf_t client_buf;
	int32_t read_len;
	uv_tcp_t *server;
	uv_tcp_t tcp;
	uv_shutdown_t shutdown_req;
} client_t;

static mcp_sc00_t status_resp = {
	.str = {
		.base = "{\"description\":\"CSPOCK IS ALIVE\",\"players\":{\"max\":1,\"online\":0},\"version\":{\"name\":\"1.7.6\",\"protocol\":5}}",
	    .len = sizeof("{\"description\":\"CSPOCK IS ALIVE\",\"players\":{\"max\":1,\"online\":0},\"version\":{\"name\":\"1.7.6\",\"protocol\":5}}") - 1
	}
};

static mcp_lc00_t lolnop = {
	.str = {
		.base = "\"lol I'm not a real server\"",
		.len = sizeof("\"lol I'm not a real server\"") - 1
	}
};

static mcp_lc00_t proto_ver_low = {
	.str = {
		.base = "\"Outdated client! Please use 1.7.6\"",
		.len = sizeof("\"Outdated client! Please use 1.7.6\"") - 1
	}
};

static mcp_lc00_t proto_ver_high = {
	.str = {
		.base = "\"Outdated server! I'm still on 1.7.6\"",
		.len = sizeof("\"Outdated server! I'm still on 1.7.6\"") - 1
	}
};

void server_write_cb(uv_write_t *req, int status)
{
	free(req->data);
	free(req);
}

void server_write_str(client_t *client, mcp_sc00_t *packet)
{
	uv_write_t *req;
	uv_buf_t buf;
	uint8_t pbuf[4096];
	int ret = mcp_encode_sc00(pbuf, packet, 4096);
	buf = uv_buf_init(memcpy(malloc(ret), pbuf, ret), ret);
	req = malloc(sizeof(*req));
	req->data = buf.base;
	uv_write(req, (uv_stream_t*)&client->tcp, &buf, 1, server_write_cb);
}

void server_write_sc01(client_t *client, mcp_sc01_t *packet)
{
	uv_write_t *req;
	uv_buf_t buf;
	uint8_t pbuf[4096];
	int ret = mcp_encode_ss01(pbuf, packet, 4096);
	buf = uv_buf_init(memcpy(malloc(ret), pbuf, ret), ret);
	req = malloc(sizeof(*req));
	req->data = buf.base;
	uv_write(req, (uv_stream_t*)&client->tcp, &buf, 1, server_write_cb);
}

client_t* client_init(client_t *client, uv_tcp_t *server, uint8_t *buf,
	size_t len)
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
	client->server = server;
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

void client_close_cb(uv_handle_t *tcp)
{
	client_t *client = (client_t*)tcp->data;
	client_buf_t *client_buf = &client->client_buf;
	free(client_buf->base);
	free(client);
}

void client_shutdown_cb(uv_shutdown_t *req, int status)
{
	printf("Shutting down a client\n");
}

void server_read_cb(uv_stream_t *tcp, ssize_t nread, const uv_buf_t *buf)
{
	client_t *client = (client_t*)tcp->data;
	client_buf_t *client_buf = &client->client_buf;
	int ret;

	if (nread < 0) {
		uv_close((uv_handle_t*)&client->tcp, client_close_cb);
		return;
	} else if (nread == 0) {
		return;
	}

	client_buf->used += nread;
	client_buf->rem  += nread;
	for(;;) {
		//If not waiting on a packet, decode next packet length
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
		ret = mcp_decode_varint(&packet_id, client_buf->cur, client_buf->rem);
		client_buf->cur += ret;
		client_buf->rem -= ret;
		switch (client->state) {
			case 0x00: switch(packet_id) {
				case 0x00: ;
					mcp_hs00_t phs00;
					ret = mcp_decode_hs00(&phs00, client_buf->cur,
						client_buf->rem, malloc);
					free(phs00.server_addr.base);
					client->state = phs00.next_state;
					if (client->state == 0x01) {
						break;
					} else if (client->state == 0x02) {
						if (phs00.protocol_version == 0x04) {
							server_write_str(client, &lolnop);
						} else if (phs00.protocol_version > 0x04) {
							server_write_str(client, &proto_ver_high);
						} else if (phs00.protocol_version < 0x04) {
							server_write_str(client, &proto_ver_low);
						}
						uv_shutdown(&client->shutdown_req,
							(uv_stream_t*)&client->tcp, client_shutdown_cb);
					} else {
						printf("Invalid state: %d\n", client->state);
						uv_close((uv_handle_t*)&client->tcp, client_close_cb);
					}
					break;
				default:
					printf("Invalid packet ID for handshake: %d\n", packet_id);
					uv_close((uv_handle_t*)&client->tcp, client_close_cb);
					ret = 0;
					break;
			} break;

			case 0x01: switch(packet_id) {
				case 0x00:
					ret = 0;
					server_write_str(client, &status_resp);
					break;
				case 0x01: ;
					mcp_sc01_t pss01;
					ret = mcp_decode_ss01(&pss01, client_buf->cur,
						client_buf->rem);
					server_write_sc01(client, &pss01);
					break;
				default:
					printf("Invalid packet ID for status: %d\n", packet_id);
					uv_close((uv_handle_t*)&client->tcp, client_close_cb);
					ret = 0;
					break;
			} break;

			case 0x02: break;

			default:
				printf("Entered state default, something is wrong, state: %d\n",
					client->state);
				break;
		}
		client_buf->cur += ret;
		client_buf->rem -= ret;
		client->read_len = -1;
	}
}

void server_connect_cb(uv_stream_t *server, int status) {
	if (status != 0) {
		printf("Connect error %s\n", uv_err_name(status));\
		return;
	}
	client_t *client = client_init(malloc(sizeof(*client)),
		(uv_tcp_t*)server, NULL, 0);
	uv_tcp_init(uv_default_loop(), &client->tcp);
	uv_accept(server, (uv_stream_t*)&client->tcp);
	uv_read_start((uv_stream_t*)&client->tcp, read_buf_alloc, server_read_cb);
}

//ToDo: Server struct for state info?
int main(int argc, char *argv[])
{
	struct sockaddr_in addr;
	uv_loop_t *loop = uv_default_loop();
	uv_ip4_addr("0.0.0.0", 25565, &addr);
	uv_tcp_t server;
	if (uv_tcp_init(loop, &server)) {
		printf("Something has gone terribly wrong\n");
		return -1;
	}
	if (uv_tcp_bind(&server, (struct sockaddr*)&addr, 0)) {
		printf("Something has gone terribly wrong2\n");
		return -1;
	}
	if (uv_listen((uv_stream_t*)&server, SOMAXCONN, server_connect_cb)) {
		printf("Something has gone terribly wrong3\n");
		return -1;
	}
	return uv_run(loop, UV_RUN_DEFAULT);
}