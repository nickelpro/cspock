#include <stdint.h>
#include <string.h>
#include "mcp.h"
#include "spocknet.h"

int encode_hs00(uint8_t *buf, uint8_t *tbuf, hs00_t *packet, size_t buf_len) {
	if(buf_len < sizeof(uint8_t)) {
		return -1;
	}
	size_t len = 1;
	int ret;
	*tbuf = 0x00;
	ret = encode_varint(tbuf + len, packet->protocol_version, buf_len - len);
	if(ret < 0) {
		return ret;
	}
	len += ret;
	ret = encode_string(tbuf + len, buf_len - len, packet->server_addr,
	 packet->addr_len);
	if(ret < 0) {
		return ret;
	}
	len += ret;
	if(buf_len - len < sizeof(uint16_t) + sizeof(uint8_t)) {
		return ret;
	}
	uint16_t port = hton16(packet->server_port);
	memcpy(tbuf+len, &port, sizeof(port));
	len += sizeof(port);
	*(tbuf + len) = packet->next_state;
	return encode_plen(buf, buf_len, tbuf, ++len);
}

//ToDo: Make sure we don't buffer overflow by checking plen
int decode_hs00(hs00_t *packet, uint8_t *buf, size_t plen) {
	int ret;
	size_t len;

	ret = decode_varint(&packet->protocol_version, buf);
	if (ret < 0) {
		return ret;
	}
	len = ret;
	ret = decode_string(&packet->server_addr, (int32_t*)&packet->addr_len,
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

int encode_sc00(uint8_t *buf, uint8_t *tbuf, sc00_t *packet, size_t buf_len) {
	if(buf_len < sizeof(uint8_t)) {
		return -1;
	}
	int ret;
	*tbuf = 0x00;
	ret = encode_string(tbuf + sizeof(uint8_t), buf_len - sizeof(uint8_t),
	 packet->resp, packet->resp_len);
	if(ret < 0) {
		return ret;
	}
	return ++ret;
}

int decode_sc00(sc00_t *packet, uint8_t *buf, size_t plen) {
	return decode_string(&packet->resp, (int32_t*)&packet->resp_len, buf);
}

int encode_sc01(uint8_t *buf, uint8_t *tbuf, sc01_t *packet, size_t buf_len) {
	if(buf_len < sizeof(uint8_t) + sizeof(int64_t)) {
		return -1;
	}
	*tbuf = 0x01;
	int64_t t = hton64(packet->ping_time);
	memcpy(tbuf + sizeof(uint8_t), &t, sizeof(int64_t));
	return sizeof(uint8_t) + sizeof(int64_t);
}

int decode_sc01(sc01_t *packet, uint8_t *buf, size_t plen) {
	packet->ping_time = ntoh64(*(int64_t*) buf);
	return sizeof(int64_t);
}

int encode_ss00(uint8_t *buf, uint8_t *tbuf, ss00_t *packet, size_t buf_len) {
	return 0;
}

int decode_ss00(ss00_t *packet, uint8_t *buf, size_t plen) {
	return 0;
}