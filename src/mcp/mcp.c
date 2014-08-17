#include <stdint.h>
#include <string.h>
#include "mcp.h"
#include "spocknet.h"

//Handshake Serverbound 0x00 Handshake
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

//Status Clientbound 0x00 Response
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

//Status Clientbound 0x01 Ping
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

//Status Serverbound 0x00 Request
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

//Login Clientbound 0x01 Encryption Request
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

//Login Clientbound 0x02 Login Success
int mcp_encode_lc02(uint8_t *buf, mcp_lc02_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(*buf)) {
		return -1;
	}
	*buf = 0x02;
	size_t len = sizeof(*buf);
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

//Login Serverbound 0x01 Encryption Response
int mcp_encode_ls01(uint8_t *buf, mcp_ls01_t *packet, size_t buf_len) {
	if (buf_len < sizeof(*buf) + packet->secret_len + packet->token_len +
		sizeof(packet->secret_len) + sizeof(packet->token_len)) {
		return -1;
	}
	*buf = 0x01;
	size_t len = sizeof(*buf);
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

//Play Clientbound 0x00 Keep Alive
int mcp_encode_pc00(uint8_t *buf, mcp_pc00_t *packet, size_t buf_len)
{
	if (buf_len < sizeof(*buf) + sizeof(packet->keep_alive)) {
		return -1;
	}
	*buf = 0x00;
	size_t len = sizeof(*buf);
	*(int32_t*)(buf + len) = hton32(packet->keep_alive);
	len += sizeof(packet->keep_alive);
	return mcp_encode_plen(buf, len, buf_len);

}

int mcp_decode_pc00(mcp_pc00_t *packet, uint8_t *buf, size_t buf_len)
{
	if (buf_len < sizeof(packet->keep_alive)) {
		return -1;
	}
	packet->keep_alive = ntoh32(*(int32_t*) buf);
	return sizeof(packet->keep_alive);
}

//Play Clientbound 0x01 Join Game
int mcp_encode_pc01(uint8_t *buf, mcp_pc01_t *packet, size_t buf_len)
{
	if (
		buf_len < sizeof(*buf) + sizeof(packet->eid) +
		sizeof(packet->gamemode) + sizeof(packet->dimension) +
		sizeof(packet->difficulty) + sizeof(packet->max_players) +
		packet->level_type.len
	) {
		return -1;
	}
	*buf = 0x01;
	size_t len = sizeof(*buf);
	*(int32_t*)(buf + len) = hton32(packet->eid);
	len += sizeof(packet->eid);
	*(buf + len) = packet->gamemode;
	len += sizeof(packet->gamemode);
	*(buf + len) = packet->difficulty;
	len += sizeof(packet->difficulty);
	*(buf + len) = packet->max_players;
	len += sizeof(packet->max_players);
	int ret = mcp_encode_str(buf + len, buf_len - len, packet->level_type);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_pc01(mcp_pc01_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	if (
		buf_len < sizeof(packet->eid) + sizeof(packet->gamemode) + 
		sizeof(packet->dimension) + sizeof(packet->difficulty) + 
		sizeof(packet->max_players)
	) {
		return -1;
	}
	size_t len = 0;
	packet->eid = ntoh32(*(int32_t*)(buf + len));
	len += sizeof(packet->eid);
	packet->gamemode = *(buf + len);
	len += sizeof(packet->gamemode);
	packet->difficulty = *(buf + len);
	len += sizeof(packet->difficulty);
	packet->max_players = *(buf + len);
	len += sizeof(packet->max_players);
	int ret = mcp_decode_str(&packet->level_type, buf + len, buf_len - len,
		mcpalloc);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	return len;
}

//Play Clientbound 0x03 Time Update
int mcp_encode_pc03(uint8_t *buf, mcp_pc03_t *packet, size_t buf_len)
{
	if (
		buf_len < sizeof(*buf) + sizeof(packet->age_of_world) + 
		sizeof(packet->time_of_day)
	) {
		return -1;
	}
	*buf = 0x03;
	size_t len = sizeof(*buf);
	*(int64_t*)(buf + len) = hton64(packet->age_of_world);
	len += sizeof(packet->age_of_world);
	*(int64_t*)(buf + len) = hton64(packet->time_of_day);
	len += sizeof(packet->time_of_day);
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_pc03(mcp_pc03_t *packet, uint8_t *buf, size_t buf_len)
{
	if (buf_len < sizeof(packet->age_of_world) + sizeof(packet->time_of_day)) {
		return -1;
	}
	size_t len = 0;
	packet->age_of_world = ntoh64(*(int64_t*)(buf + len));
	len += sizeof(packet->age_of_world);
	packet->time_of_day = ntoh64(*(int64_t*)(buf + len));
	len += sizeof(packet->time_of_day);
	return len;
}

//Play Clientbound 0x04 Entity Equipment
int mcp_encode_pc04(uint8_t *buf, mcp_pc04_t *packet, size_t buf_len)
{
	if (
		buf_len < sizeof(*buf) + sizeof(packet->eid) + 
		sizeof(packet->slot_num)
	) {
		return -1;
	}
	*buf = 0x04;
	size_t len = sizeof(*buf);
	*(int32_t*)(buf + len) = hton32(packet->eid);
	len += sizeof(packet->eid);
	*(int16_t*)(buf + len) = hton16(packet->slot_num);
	len += sizeof(packet->slot_num);
	int ret = mcp_encode_slot(buf + len, packet->item, buf_len - len);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	return mcp_encode_plen(buf, len, buf_len);
}

int mcp_decode_pc04(mcp_pc04_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	if (
		buf_len < sizeof(*buf) + sizeof(packet->eid) + 
		sizeof(packet->slot_num)
	) {
		return -1;
	}
	size_t len = 0;
	packet->eid = ntoh32(*(int32_t*)(buf + len));
	len += sizeof(packet->eid);
	packet->slot_num = ntoh16(*(int16_t*)(buf_len));
	len += sizeof(packet->slot_num);
	int ret = mcp_decode_slot(&packet->item, buf + len, buf_len - len, 
		mcpalloc);
	if (ret < 0) {
		return ret;
	}
	len += ret;
	return len;
}