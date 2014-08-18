#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "mcp.h"
#include "spocknet.h"

//Occasionally used for debugging, just leave it here until everything matures
/*
static void ByteToHex(uint8_t *bytes, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if (i > 0) printf(" ");
		printf("%02X", bytes[i]);
	}
	printf("\n");
}
*/

int mcp_encode_int8(uint8_t *buf, uint8_t num) {
	*buf = num;
	return sizeof(num);
}
int mcp_decode_int8(void *num, uint8_t *buf) {
	*(uint8_t*) num = *buf;
	return sizeof(num);
}

int mcp_encode_int16(uint8_t *buf, uint16_t num) {
	*(uint16_t*) buf = hton16(num);
	return sizeof(num);
}
int mcp_decode_int16(void *num, uint8_t *buf) {
	*(uint16_t*) num = ntoh16(*(uint16_t*) buf);
	return sizeof(num);
}

int mcp_encode_int32(uint8_t *buf, uint32_t num) {
	*(uint32_t*) buf = hton32(num);
	return sizeof(num);
}
int mcp_decode_int32(void *num, uint8_t *buf) {
	*(uint32_t*) num = ntoh32(*(uint32_t*) buf);
	return sizeof(num);
}

int mcp_encode_int64(uint8_t *buf, uint64_t num) {
	*(uint64_t*) buf = hton64(num);
	return sizeof(num);
}
int mcp_decode_int64(void *num, uint8_t *buf) {
	*(uint64_t*) num = ntoh64(*(uint64_t*) buf);
	return sizeof(num);
}

int mcp_encode_float(uint8_t *buf, float num) {
	*(float*) buf = num;
	return sizeof(num);
}
int mcp_decode_float(float *num, uint8_t *buf) {
	*num = *(float*) buf;
	return sizeof(num);
}

int mcp_encode_double(uint8_t *buf, double num) {
	*(double*) buf = num;
	return sizeof(num);
}
int mcp_decode_double(double *num, uint8_t *buf) {
	*num = *(double*) buf;
	return sizeof(num);
}

int mcp_encode_varint(uint8_t *buf, int32_t varint, size_t buf_len)
{
	size_t len = 0;
	for (; varint >= 0x80; ++buf, ++len, varint >>= 7) {
		if(len >= buf_len) {
			return -1;
		}
		*buf = 0x80|(varint&0x7F);
	}
	if(len >= buf_len) {
		return -1;
	}
	*buf = varint;
	return ++len;
}

int mcp_decode_varint(int32_t *varint, uint8_t *buf, size_t buf_len)
{
	size_t len;
	if (buf_len <= 0) {
		return -1;
	}
	for (len = 0, *varint = 0; *buf&0x80; ++buf, ++len) {
		if ((len >= 4)||(len >= buf_len)) {
			return -1;
		}
		*varint |= (*buf&0x7F)<<(len*7);
	}
	*varint |= (*buf&0x7F)<<(len*7);
	return ++len;
}

int mcp_encode_str(uint8_t *buf, mcp_str_t str, size_t buf_len)
{
	int ret = mcp_encode_varint(buf, str.len, buf_len);
	if ((ret < 0)||(ret + str.len > buf_len)) {
		return -1;
	}
	memcpy(buf + ret, str.base, str.len);
	return ret + str.len;
}

//ToDo: Error check mcpalloc
int mcp_decode_str(mcp_str_t *str, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	int ret = mcp_decode_varint(&str->len, buf, buf_len);
	if (ret < 0) {
		return ret;
	} else if (ret + str->len > buf_len) {
		return -1;
	}
	str->base = mcpalloc(str->len*sizeof(*str->base));
	memcpy(str->base, buf + ret, str->len);
	return ret + str->len;
}

int mcp_encode_slot(uint8_t *buf, mcp_slot_t slot, size_t buf_len)
{
	if (buf_len < sizeof(slot.id)) {
		return -1;
	}
	*(int16_t*) buf = hton16(slot.id);
	size_t len = sizeof(slot.id);
	if (slot.id == -1) {
		return len;
	} else if (
		buf_len < len + sizeof(slot.count) + sizeof(slot.damage) +
		sizeof(slot.nbt_len) + slot.nbt_len
	) {
		return -1;
	}
	*(buf + len) = slot.count;
	len += sizeof(slot.count);
	*(int16_t*)(buf + len) = hton16(slot.damage);
	len += sizeof(slot.damage);
	*(int16_t*)(buf + len) = hton16(slot.nbt_len);
	len += sizeof(slot.nbt_len);
	memcpy(buf + len, slot.nbt_base, slot.nbt_len);
	len += slot.nbt_len;
	return len;
}

//ToDo: Error check mcpalloc
int mcp_decode_slot(mcp_slot_t *slot, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc)
{
	if (buf_len < sizeof(slot->id)) {
		return -1;
	}
	slot->id = ntoh16(*(int16_t*) buf);
	size_t len = sizeof(slot->id);
	if (slot->id == -1) {
		slot->count = -1;
		slot->damage = -1;
		slot->nbt_len = -1;
		slot->nbt_base = NULL;
		return len;
	} else if (
		buf_len < len + sizeof(slot->count) + sizeof(slot->damage) +
		sizeof(slot->nbt_len)
	) {
		return -1;
	}
	slot->count = *(buf + len);
	len += sizeof(slot->count);
	slot->damage = ntoh16(*(int16_t*)(buf + len));
	len += sizeof(slot->damage);
	slot->nbt_len = ntoh16(*(int16_t*)(buf + len));
	len += sizeof(slot->nbt_len);
	if (buf_len < len + slot->nbt_len) {
		return -1;
	}
	slot->nbt_base = mcpalloc(slot->nbt_len);
	memcpy(slot->nbt_base, buf + len, slot->nbt_len);
	len += slot->nbt_len;
	return len;
}


int mcp_encode_plen(uint8_t *buf, size_t plen, size_t buf_len) 
{
	uint8_t tbuf[sizeof(int32_t)];
	int ret = mcp_encode_varint(tbuf, plen, sizeof(int32_t));
	if (ret < 0) {
		return ret;
	} else if (ret + plen > buf_len) {
		return -1;
	}
	memmove(buf + ret, buf, plen);
	memcpy(buf, tbuf, ret);
	return ret + plen;
}

//Consider not assigning to variable until finished calculating size
int mcp_decode_pheader(size_t *size, int32_t *id, uint8_t *buf, size_t buf_len)
{
	size_t len;
	int ret = mcp_decode_varint((int32_t*) size, buf, buf_len);
	if (ret < 0) {
		return ret;
	}
	len = ret;
	ret = mcp_decode_varint(id, buf + len, buf_len - len);
	if (ret < 0) {
		return ret;
	}
	*size -= ret;
	return len + ret;
}