#ifndef __SPOCKNET_H__
#define __SPOCKNET_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <endian.h>
#define hton16 htobe16
#define hton32 htobe32
#define hton64 htobe64
#define ntoh16 be16toh
#define ntoh32 be32toh
#define ntoh64 be64toh

#ifdef __cplusplus
}
#endif
#endif