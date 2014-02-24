#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mcp.h"

int main(int argc, char *argv[]) {
	uint8_t buf[4096], tbuf[4096];

	hs00_t handshake = {
		.protocol_version = 5,
		.addr_len         = strlen("nickg.org"),
		.server_addr      = "nickg.org",
		.server_port      = 25565,
		.next_state       = 1
	};
	int ret = encode_hs00(buf, tbuf, &handshake, 4096);
	printf("Bytes: %d\n", ret);
	ByteToHex(buf, ret);

	hs00_t decode_hand;
	size_t size;
	int32_t id;
	ret = decode_pheader(&size, &id, buf, 4096);
	ret = decode_hs00(&decode_hand, buf+ret, 4096);
	printf("Bytes: %d\n", ret);
	return 0;
}
