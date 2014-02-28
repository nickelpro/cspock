#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "mcp.h"

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

int mcp_encode_string(uint8_t *buf, size_t buf_len, char *string, 
	size_t size)
{
	int ret = mcp_encode_varint(buf, size, buf_len);
	if ((ret < 0)||(ret + size > buf_len)) {
		return -1;
	}
	memcpy(buf + ret, string, size);
	return ret + size;
}

//ToDo: Error check stralloc
int mcp_decode_string(char **string, int32_t *size, uint8_t *buf,
	size_t buf_len, mcp_str_alloc stralloc)
{
	int ret = mcp_decode_varint(size, buf, buf_len);
	if (ret < 0) {
		return ret;
	} else if (ret + *size > buf_len) {
		return -1;
	}
	*string = stralloc(*size*sizeof(**string));
	memcpy(*string, buf + ret, *size);
	return ret + *size;
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

void ByteToHex(uint8_t *bytes, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if (i > 0) printf(" ");
		printf("%02X", bytes[i]);
	}
	printf("\n");
}