#include <stdint.h>
#include <string.h>
#include "mcp.h"
#include "spocknet.h"

int mcp_encode_hs00(uint8_t *buf, mcp_hs00_t *packet, size_t buf_len) {
	if(buf_len < sizeof(uint8_t)) {
		return -1;
	}
	size_t len = 1;
	int ret;
	*buf = 0x00;
	ret = mcp_encode_varint(buf + len, packet->protocol_version, buf_len - len);
	if(ret < 0) {
		return ret;
	}
	len += ret;
	ret = mcp_encode_string(buf + len, buf_len - len, packet->server_addr,
	 packet->addr_len);
	if(ret < 0) {
		return ret;
	}
	len += ret;
	if(buf_len - len < sizeof(uint16_t) + sizeof(uint8_t)) {
		return ret;
	}
	uint16_t port = hton16(packet->server_port);
	memcpy(buf+len, &port, sizeof(port));
	len += sizeof(port);
	*(buf + len) = packet->next_state;
	return mcp_encode_plen(buf, ++len, buf_len);
}

//ToDo: Make sure we don't buffer overflow by checking plen
int mcp_decode_hs00(mcp_hs00_t *packet, uint8_t *buf, size_t plen) {
	int ret;
	size_t len;

	ret = mcp_decode_varint(&packet->protocol_version, buf);
	if (ret < 0) {
		return ret;
	}
	len = ret;
	ret = mcp_decode_string(&packet->server_addr, (int32_t*)&packet->addr_len,
	 buf + len);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	uint16_t port;
	memcpy(&port, buf + len, sizeof(port));
	packet->server_port = ntoh16(port);
	len += sizeof(port);
	packet->next_state = *(buf + len);
	return ++len;
}

int mcp_encode_sc00(uint8_t *buf, mcp_sc00_t *packet, size_t buf_len) {
	if(buf_len < sizeof(uint8_t)) {
		return -1;
	}
	int ret;
	*buf = 0x00;
	ret = mcp_encode_string(buf + sizeof(uint8_t), buf_len - sizeof(uint8_t),
	 packet->resp, packet->resp_len);
	if(ret < 0) {
		return ret;
	}
	return mcp_encode_plen(buf, ++ret + sizeof(uint8_t), buf_len);
}

int mcp_decode_sc00(mcp_sc00_t *packet, uint8_t *buf, size_t plen) {
	return mcp_decode_string(&packet->resp, (int32_t*)&packet->resp_len, buf);
}

int mcp_encode_sc01(uint8_t *buf, mcp_sc01_t *packet, size_t buf_len) {
	if(buf_len < sizeof(uint8_t) + sizeof(int64_t)) {
		return -1;
	}
	*buf = 0x01;
	int64_t t = hton64(packet->ping_time);
	memcpy(buf + sizeof(uint8_t), &t, sizeof(int64_t));
	return mcp_encode_plen(buf, sizeof(uint8_t) + sizeof(int64_t), buf_len);
}

int mcp_decode_sc01(mcp_sc01_t *packet, uint8_t *buf, size_t plen) {
	packet->ping_time = ntoh64(*(int64_t*) buf);
	return sizeof(int64_t);
}

int mcp_encode_ss00(uint8_t *buf, mcp_ss00_t *packet, size_t buf_len) {
	*buf = 0x00;
	return mcp_encode_plen(buf, sizeof(uint8_t), buf_len);
}

int mcp_decode_ss00(mcp_ss00_t *packet, uint8_t *buf, size_t plen) {
	return 0;
}