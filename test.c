#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mcp.h"

int main(int argc, char *argv[]) {
	uint8_t buf[4096];

	mcp_hs00_t handshake = {
		.protocol_version = 4,
		.addr_len         = sizeof("127.0.0.1")-1,
		.server_addr      = "127.0.0.1",
		.server_port      = 25565,
		.next_state       = 1
	};
	int ret = mcp_encode_hs00(buf, &handshake, 4096);
	printf("Bytes: %d\n", ret);
	ByteToHex(buf, ret);

	mcp_hs00_t decode_hand;
	size_t size;
	int32_t id;
	ret = mcp_decode_pheader(&size, &id, buf, 4096);
	ret = mcp_decode_hs00(&decode_hand, buf+ret, 4096);
	printf("Bytes: %d\n", ret);
	return 0;
}
