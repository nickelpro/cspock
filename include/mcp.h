#ifndef MCP_H
#define MCP_H
#ifdef __cplusplus
extern "C" {
#endif

//ToDo: Comments/Documentation

int mcp_encode_varint(uint8_t *buf, int32_t varint, size_t buf_len);
int mcp_decode_varint(int32_t *varint, uint8_t *buf, size_t buf_len);

typedef struct {
	int32_t len;
	char *base;
} mcp_str_t;

typedef void *(*mcp_alloc)(size_t size);

int mcp_encode_str(uint8_t *buf, size_t buf_len, mcp_str_t str);
int mcp_decode_str(mcp_str_t *str, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

int mcp_encode_plen(uint8_t *buf, size_t plen, size_t buf_len);

int mcp_decode_pheader(size_t *size, int32_t *id, uint8_t *buf, size_t buf_len);


//NBT




//Handshake
typedef struct {
	int32_t protocol_version;
	mcp_str_t server_addr;
	uint16_t server_port;
	uint8_t next_state;
} mcp_hs00_t;

int mcp_encode_hs00(uint8_t *buf, mcp_hs00_t *packet, size_t buf_len);
int mcp_decode_hs00(mcp_hs00_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

//Status Response
typedef struct {
	mcp_str_t str;
} mcp_sc00_t;

int mcp_encode_sc00(uint8_t *buf, mcp_sc00_t *packet, size_t buf_len);
int mcp_decode_sc00(mcp_sc00_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

//Status Ping
typedef struct {
	int64_t ping_time;
} mcp_sc01_t;

int mcp_encode_sc01(uint8_t *buf, mcp_sc01_t *packet, size_t buf_len);
int mcp_decode_sc01(mcp_sc01_t *packet, uint8_t *buf, size_t buf_len);

//Status Request
//Technically ss00 is empty, put a void pointer avoid warnings
//ToDo: ss00 shouldn't need to exist, just put up a warning to
// do no decode when the packet ID is encountered
typedef struct {
	void *ignore;
} mcp_ss00_t;

int mcp_encode_ss00(uint8_t *buf, mcp_ss00_t *packet, size_t buf_len);
int mcp_decode_ss00(mcp_ss00_t *packet, uint8_t *buf, size_t buf_len);

//Status Ping
//ss01 is identical to sc01
#define mcp_ss01_t mcp_sc01_t
#define mcp_encode_ss01 mcp_encode_sc01
#define mcp_decode_ss01 mcp_decode_sc01

//Disconnect
//lc00 is identical to sc00
#define mcp_lc00_t mcp_sc00_t
#define mcp_encode_lc00 mcp_encode_sc00
#define mcp_decode_lc00 mcp_decode_sc00

//Encryption Request
typedef struct {
	mcp_str_t server_id;
	int16_t key_len;
	uint8_t *pub_key;
	int16_t token_len;
	uint8_t *verify_token;
} mcp_lc01_t;

int mcp_encode_lc01(uint8_t *buf, mcp_lc01_t *packet, size_t buf_len);
int mcp_decode_lc01(mcp_lc01_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

//Login Success
typedef struct {
	mcp_str_t uuid;
	mcp_str_t username;
} mcp_lc02_t;

int mcp_encode_lc02(uint8_t *buf, mcp_lc02_t *packet, size_t buf_len);
int mcp_decode_lc02(mcp_lc02_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

//Login Start
//ls00 is identical to sc00
#define mcp_ls00_t mcp_sc00_t
#define mcp_encode_ls00 mcp_encode_sc00
#define mcp_decode_ls00 mcp_decode_sc00

//Encryption Response
typedef struct {
	int16_t secret_len;
	uint8_t *shared_secret;
	int16_t token_len;
	uint8_t *verify_token;
} mcp_ls01_t;

int mcp_encode_ls01(uint8_t *buf, mcp_ls01_t *packet, size_t buf_len);
int mcp_decode_ls01(mcp_ls01_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

//Keep Alive
typedef struct {
	int32_t keep_alive;
} mcp_pc00_t;

int mcp_encode_pc00(uint8_t *buf, mcp_pc00_t *packet, size_t buf_len);
int mcp_decode_pc00(mcp_pc00_t *packet, uint8_t *buf, size_t buf_len);

typedef struct {
	int32_t eid;
	uint8_t gamemode;
	int8_t dimension;
	uint8_t difficulty;
	uint8_t max_players;
	mcp_str_t level_type;

} mcp_pc01_t;


#ifdef __cplusplus
}
#endif
#endif // MCP_H