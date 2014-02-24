#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "mcp.h"

int encode_varint(uint8_t *buf, int32_t varint, size_t buf_len) {
	size_t len = 0;
	for(; varint >= 0x80; ++buf, ++len, varint >>= 7) {
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

int decode_varint(int32_t *varint, uint8_t *buf) {
	size_t len;
	for(len = 0, *varint = 0; *buf&0x80; ++buf, ++len) {
		if(len > 4) {
			return -1;
		}
		*varint |= (*buf&0x7F)<<(len*7);
	}
	*varint |= (*buf&0x7F)<<(len*7);
	return ++len;
}

int encode_string(uint8_t *buf, size_t buf_len, char *string, size_t size) {
	int ret = encode_varint(buf, size, buf_len);
	if((ret < 0)||(ret + size > buf_len)) {
		return -1;
	}
	memcpy(buf + ret, string, size);
	return ret + size;
}

//ToDo: Have func take an alloc func ptr and use that instead of malloc
//alloc func will be expected to fufill same guarantees as malloc
//ToDo: Error check malloc
//ToDo: Optional max length or error, importanrt for decode_sc00
int decode_string(char **string, int32_t *size, uint8_t *buf) {
	int ret = decode_varint(size, buf);
	if(ret < 0) {
		return ret;
	}
	*string = malloc(*size*sizeof(char));
	memcpy(*string, buf + ret, *size);
	return ret + *size;
}

int encode_plen(uint8_t *buf, size_t buf_len, uint8_t *pbuf, size_t pbuf_len) {
	int ret = encode_varint(buf, pbuf_len, buf_len);
	if(ret < 0) {
		return ret;
	} else if(ret + pbuf_len > buf_len) {
		return -1;
	}
	memcpy(buf + ret, pbuf, pbuf_len);
	return ret + pbuf_len;
}

//ToDo: Make sure we don't buffer overflow by checking buf_len
//Consider not assigning to variable until finished calculating size
int decode_pheader(size_t *size, int32_t *id, uint8_t *buf, size_t buf_len) {
	size_t len;
	int ret = decode_varint((int32_t*) size, buf);
	len = ret;
	if(ret < 0) {
		return ret;
	}
	ret = decode_varint(id, buf + len);
	if(ret < 0) {
		return ret;
	}
	*size -= ret;
	return len + ret;
}

void ByteToHex(uint8_t *bytes, size_t len) {
	size_t i;
	for (i = 0; i < len; i++) {
		if (i > 0) printf(" ");
		printf("%02X", bytes[i]);
	}
	printf("\n");
}