#define JSMN_STRICT
#include "jsmn/jsmn.h"

#include "smhasher/src/MurmurHash3.h"
#define DEDUP_MAC_NAME "mmh3-x64-128"
#define DEDUP_MAC_SIZE 128
#define DEDUP_MAC_SIZE_BYTES DEDUP_MAC_SIZE / 8
#define DEDUP_MAC_SIZE_STR DEDUP_MAC_SIZE / 4 + 1
#define DEDUP_HASH_FILENAME_MAX 512
#define mmh3 _Z19MurmurHash3_x64_128PKvijPv

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

static int dedup_hash_sprint(u_int8_t *hash, uint8_t *s) {
    int i;
    for (i=0; i < DEDUP_MAC_SIZE_BYTES; i++) {
        sprintf(s + i * 2, "%02x", hash[i]);
    }
}
