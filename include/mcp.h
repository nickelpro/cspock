#ifndef MCP_H
#define MCP_H
#ifdef __cplusplus
extern "C" {
#endif

//ToDo: Comments/Documentation

int mcp_encode_varint(uint8_t *buf, int32_t varint, size_t buf_len);

int mcp_decode_varint(int32_t *varint, uint8_t *buf, size_t buf_len);

int mcp_encode_string(uint8_t *buf, size_t buf_len, char *string, size_t size);

typedef void *(*mcp_str_alloc)(size_t size);

int mcp_decode_string(char **string, int32_t *size, uint8_t *buf,
	size_t buf_len, mcp_str_alloc stralloc);

int mcp_encode_plen(uint8_t *buf, size_t plen, size_t buf_len);

int mcp_decode_pheader(size_t *size, int32_t *id, uint8_t *buf, size_t buf_len);

void ByteToHex(uint8_t *bytes, size_t len);

typedef struct {
	int32_t protocol_version;
	size_t addr_len;
	char *server_addr;
	uint16_t server_port;
	uint8_t next_state;
} mcp_hs00_t;

int mcp_encode_hs00(uint8_t *buf, mcp_hs00_t *packet, size_t buf_len);

int mcp_decode_hs00(mcp_hs00_t *packet, uint8_t *buf, size_t buf_len,
	mcp_str_alloc stralloc);

typedef struct {
	size_t resp_len;
	char *resp;
} mcp_sc00_t;

int mcp_encode_sc00(uint8_t *buf, mcp_sc00_t *packet, size_t buf_len);

int mcp_decode_sc00(mcp_sc00_t *packet, uint8_t *buf, size_t buf_len,
	mcp_str_alloc stralloc);

typedef struct {
	int64_t ping_time;
} mcp_sc01_t;

int mcp_encode_sc01(uint8_t *buf, mcp_sc01_t *packet, size_t buf_len);

int mcp_decode_sc01(mcp_sc01_t *packet, uint8_t *buf, size_t buf_len);

//Technically ss00 is empty, put a void pointer avoid warnings
//ToDo: ss00 shouldn't need to exist, just put up a warning to
// do no decode when the packet ID is encountered
typedef struct {
	void *ignore;
} mcp_ss00_t;

int mcp_encode_ss00(uint8_t *buf, mcp_ss00_t *packet, size_t buf_len);

int mcp_decode_ss00(mcp_ss00_t *packet, uint8_t *buf, size_t buf_len);

//ss01 is identical to sc01
#define mcp_ss01_t mcp_sc01_t
#define mcp_encode_ss01 mcp_encode_sc01
#define mcp_decode_ss01 mcp_decode_sc01



#ifdef __cplusplus
}
#endif
#endif // MCP_H