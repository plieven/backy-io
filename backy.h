#include "json-parser/json.h"

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


static int hex2dec(char c)
{
    if (c >= '0' && c <= '9')
        return (int) c - '0';
    else
    {
        if (c >= 'A' && c <= 'F')
            return (int) (10 + c - 'A');
        else if (c >= 'a' && c <= 'f')
            return (int) (10 + c - 'a');
        else
            return 0;
    }
}

static int parse_json(int fd)
{
    FILE *input;
    char *buf;
    int i,j,k, ret = 1;
    size_t sz, count;
    json_value* value;

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

    value = json_parse((json_char*) buf, sz);

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
            g_crc32c_expected = (hex2dec(val->u.string.ptr[0]) << 28) +
                              (hex2dec(val->u.string.ptr[1]) << 24) +
                              (hex2dec(val->u.string.ptr[2]) << 20) +
                              (hex2dec(val->u.string.ptr[3]) << 16) +
                              (hex2dec(val->u.string.ptr[4]) << 12) +
                              (hex2dec(val->u.string.ptr[5]) << 8) +
                              (hex2dec(val->u.string.ptr[6]) << 4) +
                              (hex2dec(val->u.string.ptr[7]) << 0);
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
                unsigned long seq = strtol(val->u.object.values[j].name, NULL, 0);
                vgotoout_if_n(j != seq, "json parser error: invalid sequence in mapping: expected %lu found %lu", j, seq);
                vgotoout_if_n(entry->type != json_string, "json parser error: invalid json_type for mapping entry %lu", j);
                vgotoout_if_n(entry->u.string.length != DEDUP_MAC_SIZE / 4, "json parser error: invalid mac size in mapping: expected %d found %d", DEDUP_MAC_SIZE / 4, entry->u.string.length);
                for (k = 0; k < DEDUP_MAC_SIZE_BYTES; k++) {
                    g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + k] = (hex2dec(entry->u.string.ptr[k * 2]) << 4) +
                                                                    hex2dec(entry->u.string.ptr[k * 2 + 1]);
                }
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
    BACKY_LOG("size: %lu\n", g_filesize);

    vgotoout_if_n(g_block_count != (g_filesize + g_block_size - 1) / (g_block_size), "invalid number of chunks: expected %lu found %lu", (g_filesize + g_block_size - 1) / (g_block_size), g_block_count);

    BACKY_LOG("blockcount: %lu\n", g_block_count);

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
