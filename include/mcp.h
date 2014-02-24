#ifndef MCP_H
#define MCP_H
#ifdef __cplusplus
extern "C" {
#endif

//ToDo: Comments/Documentation

int encode_varint(uint8_t *buf, int32_t varint, size_t buf_len);

int decode_varint(int32_t *varint, uint8_t *buf);

int encode_string(uint8_t *buf, size_t buf_len, char *string, size_t size);

int decode_string(char **string, int32_t *size, uint8_t *buf);

int encode_plen(uint8_t *buf, size_t buf_len, uint8_t *pbuf, size_t pbuf_len);

int decode_pheader(size_t *size, int32_t *id, uint8_t *buf, size_t buf_len);

void ByteToHex(uint8_t *bytes, size_t len);

typedef struct {
	int32_t protocol_version;
	size_t addr_len;
	char *server_addr;
	uint16_t server_port;
	uint8_t next_state;
} hs00_t;

int encode_hs00(uint8_t *buf, uint8_t *tbuf, hs00_t *packet, size_t buf_len);

int decode_hs00(hs00_t *packet, uint8_t *buf, size_t plen);

typedef struct {
	size_t resp_len;
	char *resp;
} sc00_t;

int encode_sc00(uint8_t *buf, uint8_t *tbuf, sc00_t *packet, size_t buf_len);

int decode_sc00(sc00_t *packet, uint8_t *buf, size_t plen);

typedef struct {
	int64_t ping_time;
} sc01_t;

int encode_sc01(uint8_t *buf, uint8_t *tbuf, sc01_t *packet, size_t buf_len);

int decode_sc01(sc01_t *packet, uint8_t *buf, size_t plen);

typedef struct {
} ss00_t;

int encode_ss00(uint8_t *buf, uint8_t *tbuf, ss00_t *packet, size_t buf_len);

int decode_ss00(ss00_t *packet, uint8_t *buf, size_t plen);

//ss01 is identical to sc01
#define ss01_t sc01_t
#define encode_ss01 encode_sc01
#define decode_ss01 decode_sc01

#ifdef __cplusplus
}
#endif
#endif // MCP_H