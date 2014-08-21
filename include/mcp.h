#ifndef MCP_H
#define MCP_H
#ifdef __cplusplus
extern "C" {
#endif

//ToDo: Comments/Documentation

int mcp_encode_int8(uint8_t *buf, uint8_t num);
int mcp_decode_int8(uint8_t *num, uint8_t *buf);
int mcp_encode_int16(uint8_t *buf, uint16_t num);
int mcp_decode_int16(uint16_t *num, uint8_t *buf);
int mcp_encode_int32(uint8_t *buf, uint32_t num);
int mcp_decode_int32(uint32_t *num, uint8_t *buf);
int mcp_encode_int64(uint8_t *buf, uint64_t num);
int mcp_decode_int64(uint64_t *num, uint8_t *buf);
int mcp_encode_float(uint8_t *buf, float num);
int mcp_decode_float(float *num, uint8_t *buf);
int mcp_encode_double(uint8_t *buf, double num);
int mcp_decode_double(double *num, uint8_t *buf);

typedef void *(*mcp_alloc)(size_t size);

int mcp_encode_varint(uint8_t *buf, int32_t varint, size_t buf_len);
int mcp_decode_varint(int32_t *varint, uint8_t *buf, size_t buf_len);

typedef struct {
	int32_t len;
	char *base;
} mcp_str_t;

int mcp_encode_str(uint8_t *buf, mcp_str_t str, size_t buf_len);
int mcp_decode_str(mcp_str_t *str, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

typedef struct {
	int16_t id;
	int8_t count;
	int16_t damage;
	int16_t nbt_len;
	uint8_t *nbt_base;
} mcp_slot_t;

int mcp_encode_slot(uint8_t *buf, mcp_slot_t slot, size_t buf_len);
int mcp_decode_slot(mcp_slot_t *slot, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

typedef struct {
	uint8_t index;
	enum {
		MCP_METANUM8_T,
		MCP_METANUM16_T,
		MCP_METANUM32_T,
		MCP_METANUMF_T,
		MCP_METASTR_T,
		MCP_METASLOT_T,
		MCP_METAARR_T
	} type_id;
	union {
		int8_t num8;
		int16_t num16;
		int32_t num32;
		float numf;
		mcp_str_t str;
		mcp_slot_t slot;
		int32_t arr[3];
	};
} mcp_metaobj_t;

typedef struct {
	size_t len;
	mcp_metaobj_t *objs;
} mcp_meta_t;

int mcp_encode_meta(uint8_t *buf, mcp_meta_t meta, size_t buf_len);
int mcp_decode_meta(mcp_meta_t *meta, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

int mcp_encode_plen(uint8_t *buf, size_t plen, size_t buf_len);

int mcp_decode_pheader(size_t *size, int32_t *id, uint8_t *buf,
	size_t buf_len);


//Handshake Serverbound 0x00 Handshake
typedef struct {
	int32_t protocol_version;
	mcp_str_t server_addr;
	uint16_t server_port;
	uint8_t next_state;
} mcp_hs00_t;

int mcp_encode_hs00(uint8_t *buf, mcp_hs00_t *packet, size_t buf_len);
int mcp_decode_hs00(mcp_hs00_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

//Status Clientbound 0x00 Response
typedef struct {
	mcp_str_t str;
} mcp_sc00_t;

int mcp_encode_sc00(uint8_t *buf, mcp_sc00_t *packet, size_t buf_len);
int mcp_decode_sc00(mcp_sc00_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

//Status Clientbound 0x01 Ping
typedef struct {
	int64_t ping_time;
} mcp_sc01_t;

int mcp_encode_sc01(uint8_t *buf, mcp_sc01_t *packet, size_t buf_len);
int mcp_decode_sc01(mcp_sc01_t *packet, uint8_t *buf, size_t buf_len);

//Status Serverbound 0x00 Request
//Technically ss00 is empty, put a void pointer avoid warnings
//ToDo: ss00 shouldn't need to exist, just put up a warning to
// do no decode when the packet ID is encountered
typedef struct {
	void *ignore;
} mcp_ss00_t;

int mcp_encode_ss00(uint8_t *buf, mcp_ss00_t *packet, size_t buf_len);
int mcp_decode_ss00(mcp_ss00_t *packet, uint8_t *buf, size_t buf_len);

//Status Serverbound 0x01 Ping
//ss01 is identical to sc01
#define mcp_ss01_t mcp_sc01_t
#define mcp_encode_ss01 mcp_encode_sc01
#define mcp_decode_ss01 mcp_decode_sc01

//Login Clientbound 0x00 Disconnect
//lc00 is identical to sc00
#define mcp_lc00_t mcp_sc00_t
#define mcp_encode_lc00 mcp_encode_sc00
#define mcp_decode_lc00 mcp_decode_sc00

//Login Clientbound 0x01 Encryption Request
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

//Login Clientbound 0x02 Login Success
typedef struct {
	mcp_str_t uuid;
	mcp_str_t username;
} mcp_lc02_t;

int mcp_encode_lc02(uint8_t *buf, mcp_lc02_t *packet, size_t buf_len);
int mcp_decode_lc02(mcp_lc02_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

//Login Serverbound 0x00 Login Start
//ls00 is identical to sc00
#define mcp_ls00_t mcp_sc00_t
#define mcp_encode_ls00 mcp_encode_sc00
#define mcp_decode_ls00 mcp_decode_sc00

//Login Serverbound 0x01 Encryption Response
typedef struct {
	int16_t secret_len;
	uint8_t *shared_secret;
	int16_t token_len;
	uint8_t *verify_token;
} mcp_ls01_t;

int mcp_encode_ls01(uint8_t *buf, mcp_ls01_t *packet, size_t buf_len);
int mcp_decode_ls01(mcp_ls01_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

//Play Clientbound 0x00 Keep Alive
typedef struct {
	int32_t keep_alive;
} mcp_pc00_t;

int mcp_encode_pc00(uint8_t *buf, mcp_pc00_t *packet, size_t buf_len);
int mcp_decode_pc00(mcp_pc00_t *packet, uint8_t *buf, size_t buf_len);

//Play Clientbound 0x01 Join Game
typedef struct {
	int32_t eid;
	uint8_t gamemode;
	int8_t dimension;
	uint8_t difficulty;
	uint8_t max_players;
	mcp_str_t level_type;
} mcp_pc01_t;

int mcp_encode_pc01(uint8_t *buf, mcp_pc01_t *packet, size_t buf_len);
int mcp_decode_pc01(mcp_pc01_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

//Play Clientbound 0x02 Chat Message
typedef struct {
	mcp_str_t json_data;
} mcp_pc02_t;

int mcp_encode_pc02(uint8_t *buf, mcp_pc02_t *packet, size_t buf_len);
int mcp_decode_pc02(mcp_pc02_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

//Play Clientbound 0x03 Time Update
typedef struct {
	int64_t age_of_world;
	int64_t time_of_day;
} mcp_pc03_t;

int mcp_encode_pc03(uint8_t *buf, mcp_pc03_t *packet, size_t buf_len);
int mcp_decode_pc03(mcp_pc03_t *packet, uint8_t *buf, size_t buf_len);

//Play Clientbound 0x04 Entity Equipment
typedef struct {
	int32_t eid;
	int16_t slot_num;
	mcp_slot_t item;
} mcp_pc04_t;

int mcp_encode_pc04(uint8_t *buf, mcp_pc04_t *packet, size_t buf_len);
int mcp_decode_pc04(mcp_pc04_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

//Play Clientbound 0x05 Spawn Position
typedef struct {
	int32_t x;
	int32_t y;
	int32_t z;
} mcp_pc05_t;

int mcp_encode_pc05(uint8_t *buf, mcp_pc05_t *packet, size_t buf_len);
int mcp_decode_pc05(mcp_pc05_t *packet, uint8_t *buf, size_t buf_len);

//Play Clientbound 0x06 Update Health
typedef struct {
	float health;
	int16_t food;
	float saturation;
} mcp_pc06_t;

int mcp_encode_pc06(uint8_t *buf, mcp_pc06_t *packet, size_t buf_len);
int mcp_decode_pc06(mcp_pc06_t *packet, uint8_t *buf, size_t buf_len);

//Play Clientbound 0x07 Respawn
typedef struct {
	int32_t dimension;
	uint8_t difficulty;
	uint8_t gamemode;
	mcp_str_t level_type;
} mcp_pc07_t;

int mcp_encode_pc07(uint8_t *buf, mcp_pc07_t *packet, size_t buf_len);
int mcp_decode_pc07(mcp_pc07_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

//Play Clientbound 0x08 Player Position and Look
typedef struct {
	double x;
	double y;
	double z;
	float yaw;
	float pitch;
	uint8_t on_ground;
} mcp_pc08_t;

int mcp_encode_pc08(uint8_t *buf, mcp_pc08_t *packet, size_t buf_len);
int mcp_decode_pc08(mcp_pc08_t *packet, uint8_t *buf, size_t buf_len);

//Play Clientbound 0x09 Held Item Change
typedef struct {
	int8_t slot_num;
} mcp_pc09_t;

int mcp_encode_pc09(uint8_t *buf, mcp_pc09_t *packet, size_t buf_len);
int mcp_decode_pc09(mcp_pc09_t *packet, uint8_t *buf, size_t buf_len);

//Play Clientbound 0x0A Use Bed
typedef struct {
	int32_t eid;
	int32_t x;
	uint8_t y;
	int32_t z;
} mcp_pc0A_t;

int mcp_encode_pc0A(uint8_t *buf, mcp_pc0A_t *packet, size_t buf_len);
int mcp_decode_pc0A(mcp_pc0A_t *packet, uint8_t *buf, size_t buf_len);

//Play Clientbound 0x0B Animation
typedef struct {
	int32_t eid;
	uint8_t animation;
} mcp_pc0B_t;

int mcp_encode_pc0B(uint8_t *buf, mcp_pc0B_t *packet, size_t buf_len);
int mcp_decode_pc0B(mcp_pc0B_t *packet, uint8_t *buf, size_t buf_len);

//Play Clientbound 0x0C Spawn Player
typedef struct {
	int32_t eid;
	mcp_str_t uuid;
	mcp_str_t name;
	int32_t data_count;
	size_t prop_len;
	struct {
		mcp_str_t name;
		mcp_str_t val;
		mcp_str_t sig;
	} *props;
	int32_t x;
	int32_t y;
	int8_t yaw;
	int8_t pitch;
	int16_t current_item;
	size_t metadata_len;
	mcp_meta_t metadata;
} mcp_pc0C_t;

int mcp_encode_pc0C(uint8_t *buf, mcp_pc0C_t *packet, size_t buf_len);
int mcp_decode_pc0C(mcp_pc0C_t *packet, uint8_t *buf, size_t buf_len,
	mcp_alloc mcpalloc);

#ifdef __cplusplus
}
#endif
#endif // MCP_H