#include <inttypes.h>
#include "json-parser/json.h"
#include "smhasher/src/MurmurHash3.h"
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/fcntl.h>
#include <utime.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <stdint.h>
#include <malloc.h>     /* valloc() */
#include <libgen.h>

extern void _Z19MurmurHash3_x64_128PKvijPv ( const void * key, int len, uint32_t seed, void * out );

#define DEDUP_MAC_NAME "mmh3-x64-128"
#define DEDUP_MAC_SIZE 128
#define DEDUP_MAC_SIZE_BYTES DEDUP_MAC_SIZE / 8
#define DEDUP_MAC_SIZE_STR DEDUP_MAC_SIZE / 4 + 1
#define DEDUP_HASH_FILENAME_MAX 512
#define mmh3 _Z19MurmurHash3_x64_128PKvijPv

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#if DEDUP_MAC_SIZE_BYTES == 16
static int inline __attribute__((always_inline)) dedup_hash_sprint(u_int8_t *hash, uint8_t *s) {
    static const char *d2h = "0123456789abcdef";
    s[0] = d2h[(hash[0] >> 4) & 0xf];
    s[1] = d2h[hash[0] & 0xf];
    s[2] = d2h[(hash[1] >> 4) & 0xf];
    s[3] = d2h[hash[1] & 0xf];
    s[4] = d2h[(hash[2] >> 4) & 0xf];
    s[5] = d2h[hash[2] & 0xf];
    s[6] = d2h[(hash[3] >> 4) & 0xf];
    s[7] = d2h[hash[3] & 0xf];
    s[8] = d2h[(hash[4] >> 4) & 0xf];
    s[9] = d2h[hash[4] & 0xf];
    s[10] = d2h[(hash[5] >> 4) & 0xf];
    s[11] = d2h[hash[5] & 0xf];
    s[12] = d2h[(hash[6] >> 4) & 0xf];
    s[13] = d2h[hash[6] & 0xf];
    s[14] = d2h[(hash[7] >> 4) & 0xf];
    s[15] = d2h[hash[7] & 0xf];
    s[16] = d2h[(hash[8] >> 4) & 0xf];
    s[17] = d2h[hash[8] & 0xf];
    s[18] = d2h[(hash[9] >> 4) & 0xf];
    s[19] = d2h[hash[9] & 0xf];
    s[20] = d2h[(hash[10] >> 4) & 0xf];
    s[21] = d2h[hash[10] & 0xf];
    s[22] = d2h[(hash[11] >> 4) & 0xf];
    s[23] = d2h[hash[11] & 0xf];
    s[24] = d2h[(hash[12] >> 4) & 0xf];
    s[25] = d2h[hash[12] & 0xf];
    s[26] = d2h[(hash[13] >> 4) & 0xf];
    s[27] = d2h[hash[13] & 0xf];
    s[28] = d2h[(hash[14] >> 4) & 0xf];
    s[29] = d2h[hash[14] & 0xf];
    s[30] = d2h[(hash[15] >> 4) & 0xf];
    s[31] = d2h[hash[15] & 0xf];
}
#else
static int inline __attribute__((always_inline)) dedup_hash_sprint(u_int8_t *hash, uint8_t *s) {
    int i;
    static const char *d2h = "0123456789abcdef";
    for (i = 0; i < DEDUP_MAC_SIZE_BYTES; i++, s+=2, hash++)
    {
        s[0] = d2h[(hash[0] >> 4) & 0xf];
        s[1] = d2h[hash[0] & 0xf];
    }
}
#endif

#define CBLK_SIZE           (4*1024*1024)  /* Default block size - 4096KB */
#define MIN_CBLK_SIZE       (64*1024)     /* 256KByte */
#define MAX_CBLK_SIZE       (16*1024*1024) /* 16MiB */

static void *g_zeroblock = NULL;
static unsigned int g_block_size = CBLK_SIZE;
static unsigned int g_version = 1;
static uint64_t g_filesize = 0;     /* size of the uncompressed data */
static uint64_t g_block_count = 0;
static char* g_block_mapping = NULL;
static uint8_t* g_block_is_compressed = NULL;
static char g_zeroblock_hash[DEDUP_MAC_SIZE_BYTES];
static char *g_metadata = NULL;
static uint32_t g_crc32c_expected = 0xffffffff;

static char g_estr_malloc[] =       "malloc";
#define ESTR_MALLOC         g_estr_malloc
static char g_estr_fdopen[] =       "fdopen";
#define ESTR_FDOPEN         g_estr_fdopen
static char g_estr_fread[] =        "fread";
#define ESTR_FREAD          g_estr_fread

#define DIAG_NOT_ERRNO      (-1)

/*
 * diag -   Print a diagnostic; preceded by g_arg0.
 *
 *  error   errno value (not used if < 0)
 *  format  printf-style format string
 *  ... arguments to be inserted into diagnostic
 */
static void
diag(int error, char *format, ...)
{
    va_list ap;
    char *error_str;

    (void) fprintf(stderr, "\nFATAL ERROR! ");
    va_start(ap, format);
    (void) vfprintf(stderr, format, ap);
    va_end(ap);
    if (error != DIAG_NOT_ERRNO) {
        error_str = strerror(error);
        if (! error_str)
            error_str = strerror(0);
        (void) fprintf(stderr, ": %s (%d)\n", error_str,error);
    } else {
        fprintf(stderr, "\n");
    }
}

pthread_mutex_t log_mutex;

#define BACKY_LOG(format, args...) \
    do { \
        pthread_mutex_lock(&log_mutex); \
        fprintf(stderr, format, ## args); \
        fflush(stderr); \
        pthread_mutex_unlock(&log_mutex); \
    } while (0)

#define die_if(cond, str)   { \
    if (cond) { \
        diag(errno, str); exit(1); } }
#define vdie_if(cond, str, ...) { \
    if (cond) { \
        diag(errno, str, __VA_ARGS__); exit(1); } }
#define vdie_if_n(cond, str, ...) { \
    if (cond) { \
        diag(DIAG_NOT_ERRNO, str, __VA_ARGS__); exit(1); } }

#define vgotoout_if_n(cond, str, ...) { \
    if (cond) { \
        diag(DIAG_NOT_ERRNO, str, __VA_ARGS__); goto out; } }

static const char h2d[256] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0,0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

static int parse_json(int fd)
{
    FILE *input;
    char *buf;
    int i, j, ret = 1;
    size_t sz, count;
    json_value* value;
    struct timespec tstart={}, tend={};

    input = fdopen(fd, "r");
    die_if(! input, ESTR_FDOPEN);

    fseek(input, 0L, SEEK_END);
    sz = ftell(input);
    buf = malloc(sz);
    die_if(!buf, ESTR_MALLOC);

    rewind(input);

    count = fread(buf, 1, sz, input);
    die_if(count != sz, ESTR_FREAD);

    fclose(input);

    json_settings settings = { .settings = json_fast_string_parse };

    clock_gettime(CLOCK_MONOTONIC, &tstart);
    value = json_parse_ex(&settings, (json_char*) buf, sz, 0);
    clock_gettime(CLOCK_MONOTONIC, &tend);

    fprintf(stderr, "parse_json (core) took about %.5f seconds\n",
            ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
            ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));

    vgotoout_if_n(!value || value->type != json_object, "json parse error", 0);

    for (i = 0; i < value->u.object.length; i++) {
        json_char *name = value->u.object.values[i].name;
        json_value *val = value->u.object.values[i].value;
        if (val->type == json_integer && !strcmp(name, "size")) {
            g_filesize = val->u.integer;
        } else if (val->type == json_integer && !strcmp(name, "blocksize")) {
            g_block_size = val->u.integer;
        } else if (val->type == json_integer && !strcmp(name, "version")) {
            g_version = val->u.integer;
        } else if (val->type == json_string && !strcmp(name, "hash")) {
            vgotoout_if_n(val->u.string.length != strlen(DEDUP_MAC_NAME) || strncmp(DEDUP_MAC_NAME, val->u.string.ptr, strlen(DEDUP_MAC_NAME)), "unsupported hash: '%.*s'", val->u.string.length, val->u.string.ptr);
        } else if (val->type == json_string && !strcmp(name, "crc32c")) {
            g_crc32c_expected = (h2d[val->u.string.ptr[0]] << 28) +
                                (h2d[val->u.string.ptr[1]] << 24) +
                                (h2d[val->u.string.ptr[2]] << 20) +
                                (h2d[val->u.string.ptr[3]] << 16) +
                                (h2d[val->u.string.ptr[4]] << 12) +
                                (h2d[val->u.string.ptr[5]] << 8) +
                                (h2d[val->u.string.ptr[6]] << 4) +
                                (h2d[val->u.string.ptr[7]] << 0);
            BACKY_LOG("g_crc32c_expected: %08x\n", g_crc32c_expected);
        } else if (val->type == json_object && !strcmp(name, "metadata")) {
            g_metadata = malloc(val->u.object.sz + 1);
            die_if(!g_metadata, ESTR_MALLOC);
            g_metadata[val->u.object.sz] = 0;
            g_metadata = memcpy(g_metadata, val->u.object.ptr, val->u.object.sz);
            BACKY_LOG("metadata: %s\n", g_metadata);
        } else if (val->type == json_object && !strcmp(name, "mapping")) {
            g_block_count = val->u.object.length;
            die_if(g_block_mapping, ESTR_MALLOC);
            g_block_mapping = malloc((DEDUP_MAC_SIZE_BYTES) * g_block_count);
            die_if(!g_block_mapping, ESTR_MALLOC);
            g_block_is_compressed = malloc(g_block_count);
            die_if(!g_block_is_compressed, ESTR_MALLOC);
            for (j = 0; j < g_block_count; j++) {
                json_value *entry = val->u.object.values[j].value;
                unsigned long seq = strtoul(val->u.object.values[j].name, NULL, 0);
                vgotoout_if_n(j != seq, "json parser error: invalid sequence in mapping: expected %lu found %lu", j, seq);
                vgotoout_if_n(entry->type != json_string, "json parser error: invalid json_type for mapping entry %lu", j);
                vgotoout_if_n(entry->u.string.length != DEDUP_MAC_SIZE / 4, "json parser error: invalid mac size in mapping: expected %d found %d", DEDUP_MAC_SIZE / 4, entry->u.string.length);
#if DEDUP_MAC_SIZE_BYTES == 16
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 0] = (h2d[entry->u.string.ptr[0 * 2]] << 4) +
                                                                   h2d[entry->u.string.ptr[0 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 1] = (h2d[entry->u.string.ptr[1 * 2]] << 4) +
                                                                   h2d[entry->u.string.ptr[1 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 2] = (h2d[entry->u.string.ptr[2 * 2]] << 4) +
                                                                   h2d[entry->u.string.ptr[2 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 3] = (h2d[entry->u.string.ptr[3 * 2]] << 4) +
                                                                   h2d[entry->u.string.ptr[3 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 4] = (h2d[entry->u.string.ptr[4 * 2]] << 4) +
                                                                   h2d[entry->u.string.ptr[4 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 5] = (h2d[entry->u.string.ptr[5 * 2]] << 4) +
                                                                   h2d[entry->u.string.ptr[5 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 6] = (h2d[entry->u.string.ptr[6 * 2]] << 4) +
                                                                   h2d[entry->u.string.ptr[6 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 7] = (h2d[entry->u.string.ptr[7 * 2]] << 4) +
                                                                   h2d[entry->u.string.ptr[7 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 8] = (h2d[entry->u.string.ptr[8 * 2]] << 4) +
                                                                   h2d[entry->u.string.ptr[8 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 9] = (h2d[entry->u.string.ptr[9 * 2]] << 4) +
                                                                   h2d[entry->u.string.ptr[9 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 10] = (h2d[entry->u.string.ptr[10 * 2]] << 4) +
                                                                    h2d[entry->u.string.ptr[10 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 11] = (h2d[entry->u.string.ptr[11 * 2]] << 4) +
                                                                    h2d[entry->u.string.ptr[11 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 12] = (h2d[entry->u.string.ptr[12 * 2]] << 4) +
                                                                    h2d[entry->u.string.ptr[12 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 13] = (h2d[entry->u.string.ptr[13 * 2]] << 4) +
                                                                    h2d[entry->u.string.ptr[13 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 14] = (h2d[entry->u.string.ptr[14 * 2]] << 4) +
                                                                    h2d[entry->u.string.ptr[14 * 2 + 1]];
                g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + 15] = (h2d[entry->u.string.ptr[15 * 2]] << 4) +
                                                                    h2d[entry->u.string.ptr[15 * 2 + 1]];
#else
                int k;
                for (k = 0; k < DEDUP_MAC_SIZE_BYTES; k++) {
                    g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + k] = (h2d[entry->u.string.ptr[k * 2]] << 4) +
                                                                       h2d[entry->u.string.ptr[k * 2 + 1]];
                }
#endif
            }
        } else {
            vgotoout_if_n(1, "json parser error: unexpected token '%s' (type %d)", name, val->type);
        }
    }

    vgotoout_if_n(g_version < 1 || g_version > 2, "unsupported version %d", g_version);
    vgotoout_if_n(g_version == 1 && g_block_size != 4096*1024, "unsupported version 1 block size %lu", g_block_size);
    vgotoout_if_n(g_block_size % MIN_CBLK_SIZE || g_block_size < MIN_CBLK_SIZE || g_block_size > MAX_CBLK_SIZE, "unsupported block size %lu", g_block_size);

    BACKY_LOG("version: %d\n", g_version);
    BACKY_LOG("blocksize: %u\n", g_block_size);
    BACKY_LOG("size: %" PRIu64 "\n", g_filesize);

    vgotoout_if_n(g_block_count != (g_filesize + g_block_size - 1) / (g_block_size), "invalid number of chunks: expected %lu found %lu", (g_filesize + g_block_size - 1) / (g_block_size), g_block_count);

    BACKY_LOG("blockcount: %" PRIu64 "\n", g_block_count);

    ret = 0;
out:
    free(buf);
    json_value_free(value);

    return ret;
}

static void g_free() {
    free(g_zeroblock);
    g_zeroblock = NULL;
    free(g_metadata);
    g_metadata = NULL;
    free(g_block_mapping);
    g_block_mapping = NULL;
    free(g_block_is_compressed);
    g_block_is_compressed = NULL;
    g_block_size = CBLK_SIZE;
    g_version = 1;
    g_filesize = 0;     /* size of the uncompressed data */
    g_block_count = 0;
    g_crc32c_expected = 0xffffffff;
}
