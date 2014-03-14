#include <stdint.h>
#include <string.h>
#include "mcp.h"
#include "spocknet.h"

int mcp_encode_hs00(uint8_t *buf, mcp_hs00_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(*buf)) {
		return -1;
	}
	*buf = 0x00;
	size_t len = sizeof(*buf);
	int ret;
	ret = mcp_encode_varint(buf + len, packet->protocol_version,
		buf_len - len);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	ret = mcp_encode_str(buf + len, buf_len - len, packet->server_addr);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	if (buf_len - len < sizeof(packet->server_port) + sizeof(*buf)) {
		return -1;
	}
	*(uint16_t*)(buf + len) = hton16(packet->server_port);
	len += sizeof(packet->server_port);
	*(buf + len) = packet->next_state;
	len += sizeof(packet->next_state);
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_hs00(mcp_hs00_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	int ret;
	size_t len;

	ret = mcp_decode_varint(&packet->protocol_version, buf, buf_len);
	if (ret < 0) {
		return ret;
	}
	len = ret;
	ret = mcp_decode_str(&packet->server_addr, buf + len, buf_len - len,
		mcpalloc);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	if (buf_len < len + sizeof(packet->server_port)) {
		return -1;
	}
	packet->server_port = ntoh16(*(uint16_t*)(buf + len));
	len += sizeof(packet->server_port);
	packet->next_state = *(buf + len);
	len += sizeof(packet->next_state);
	return len;
}

int mcp_encode_sc00(uint8_t *buf, mcp_sc00_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(*buf)) {
		return -1;
	}
	*buf = 0x00;
	int ret;
	ret = mcp_encode_str(buf + sizeof(*buf), buf_len - sizeof(*buf),
		packet->str);
	if (ret < 0) {
		return ret;
	}
	return mcp_encode_plen(buf, sizeof(*buf) + ret, buf_len);
}

int mcp_decode_sc00(mcp_sc00_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	return mcp_decode_str(&packet->str, buf, buf_len, mcpalloc);
}

int mcp_encode_sc01(uint8_t *buf, mcp_sc01_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(*buf) + sizeof(packet->ping_time)) {
		return -1;
	}
	*buf = 0x01;
	*(int64_t*)(buf + sizeof(*buf)) = hton64(packet->ping_time);
	return mcp_encode_plen(buf, sizeof(*buf) + sizeof(packet->ping_time),
		buf_len);
}

int mcp_decode_sc01(mcp_sc01_t *packet, uint8_t *buf, size_t buf_len)
{
	if (buf_len < sizeof(packet->ping_time)) {
		return -1;
	}
	packet->ping_time = ntoh64(*(int64_t*) buf);
	return sizeof(packet->ping_time);
}

int mcp_encode_ss00(uint8_t *buf, mcp_ss00_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(*buf)) {
		return -1;
	}
	*buf = 0x00;
	return mcp_encode_plen(buf, sizeof(*buf), buf_len);
}

int mcp_decode_ss00(mcp_ss00_t *packet, uint8_t *buf, size_t buf_len)
{
	return 0;
}

int mcp_encode_lc01(uint8_t *buf, mcp_lc01_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(*buf)) {
		return -1;
	}
	*buf = 0x01;
	size_t len = sizeof(*buf);
	int ret;
	ret = mcp_encode_str(buf + len, buf_len - len, packet->server_id);
	if (ret < 0) {
		return ret;
	} else if (buf_len < ret + len + packet->key_len + packet->token_len +
		sizeof(packet->key_len) + sizeof(packet->token_len)) {
		return -1;
	}
	len += ret;
	*(int16_t*)(buf + len) = hton16(packet->key_len);
	len += sizeof(packet->key_len);
	memcpy(buf + len, packet->pub_key, packet->key_len);
	len += packet->key_len;
	*(int16_t*)(buf + len) = hton16(packet->token_len);
	len += sizeof(packet->token_len);
	memcpy(buf + len, packet->verify_token, packet->token_len);
	len += packet->token_len;
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_lc01(mcp_lc01_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	size_t len;
	int ret;
	ret = mcp_decode_str(&packet->server_id, buf, buf_len, mcpalloc);
	if (ret < 0) {
		return ret;
	}
	len = ret;
	if (buf_len < len + sizeof(packet->key_len)) {
		return -1;
	}
	packet->key_len = ntoh16(*(uint16_t*)(buf + len));
	len += sizeof(packet->key_len);
	if (buf_len < len + packet->key_len) {
		return -1;
	}
	packet->pub_key = memcpy(mcpalloc(packet->key_len), buf + len,
		packet->key_len);
	len += packet->key_len;
	if (buf_len < len + sizeof(packet->token_len)) {
		return -1;
	}
	packet->token_len = ntoh16(*(uint16_t*)(buf + len));
	len += sizeof(packet->token_len);
	if (buf_len < len + packet->token_len) {
		return -1;
	}
	packet->verify_token = memcpy(mcpalloc(packet->token_len), buf + len,
		packet->token_len);
	len += packet->token_len;
	return len;
}

int mcp_encode_lc02(uint8_t *buf, mcp_lc02_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(*buf)) {
		return -1;
	}
	*buf = 0x02;
	size_t len = 1;
	int ret;
	ret = mcp_encode_str(buf + len, buf_len - len, packet->uuid);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	ret = mcp_encode_str(buf + len, buf_len - len, packet->username);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_lc02(mcp_lc02_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	size_t len;
	int ret;
	ret = mcp_decode_str(&packet->uuid, buf, buf_len, mcpalloc);
	if (ret < 0) {
		return ret;
	}
	len = ret;
	ret = mcp_decode_str(&packet->username, buf + len, buf_len - len,
		mcpalloc);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	return len;
}

int mcp_encode_ls01(uint8_t *buf, mcp_ls01_t *packet, size_t buf_len) {
	if (buf_len < sizeof(*buf) + packet->secret_len + packet->token_len +
		sizeof(packet->secret_len) + sizeof(packet->token_len)) {
		return -1;
	}
	*buf = 0x01;
	size_t len = 1;
	*(int16_t*)(buf + len) = hton16(packet->secret_len);
	len += sizeof(packet->secret_len);
	memcpy(buf + len, packet->shared_secret, packet->secret_len);
	len += packet->secret_len;
	*(int16_t*)(buf + len) = hton16(packet->token_len);
	len += sizeof(packet->token_len);
	memcpy(buf + len, packet->verify_token, packet->token_len);
	len += packet->token_len;
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_ls01(mcp_ls01_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	size_t len = 0;
	if (buf_len < len + sizeof(packet->secret_len)) {
		return -1;
	}
	packet->secret_len = ntoh16(*(uint16_t*)(buf + len));
	len += sizeof(packet->secret_len);
	if (buf_len < len + packet->secret_len) {
		return -1;
	}
	packet->shared_secret = memcpy(mcpalloc(packet->secret_len), buf + len,
		packet->secret_len);
	len += packet->secret_len;
	if (buf_len < len + sizeof(packet->token_len)) {
		return -1;
	}
	packet->token_len = ntoh16(*(uint16_t*)(buf + len));
	len += sizeof(packet->token_len);
	if (buf_len < len + packet->token_len) {
		return -1;
	}
	packet->verify_token = memcpy(mcpalloc(packet->token_len), buf + len,
		packet->token_len);
	len += packet->token_len;
	return len;
}