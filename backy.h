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

#define CBLK_SIZE           (4*1024*1024)  /* Default block size - 4096KB */
#define MIN_CBLK_SIZE       (64*1024)     /* 256KByte */
#define MAX_CBLK_SIZE       (16*1024*1024) /* 16MiB */

static char *g_arg0;        /* Program name */
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

    (void) fprintf(stderr, "\nFATAL ERROR!\n%s: ", g_arg0);
    va_start(ap, format);
    (void) vfprintf(stderr, format, ap);
    va_end(ap);
    if (error != DIAG_NOT_ERRNO) {
        error_str = strerror(error);
        if (! error_str)
            error_str = strerror(0);
        (void) fprintf(stderr, ": %s (%d)\n", error_str,error);
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

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
            strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

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

static void parse_json(int fd)
{
    FILE *input;
    char *buf;
    int i,j,k;
    size_t sz, count;
    jsmn_parser parser;
    jsmntok_t *tok;
    int tokencnt;

    input = fdopen(fd, "r");
    die_if(! input, ESTR_FDOPEN);

    fseek(input, 0L, SEEK_END);
    sz = ftell(input);
    buf = malloc(sz);
    die_if(!buf, ESTR_MALLOC);

    rewind(input);

    count = fread(buf, 1, sz, input);
    die_if(count != sz, ESTR_FREAD);

    jsmn_init(&parser);
    tokencnt = jsmn_parse(&parser, buf, sz, NULL, 0);

    tok = malloc(sizeof(*tok) * tokencnt);
    die_if(!tok, ESTR_MALLOC);

    jsmn_init(&parser);
    vdie_if_n(tokencnt != jsmn_parse(&parser, buf, sz, tok, tokencnt), "json parse error", 0);

    for (i = 1; i < tokencnt; i++) {
        if (jsoneq(buf, tok + i, "size") == 0) {
            g_filesize = strtol(buf + (tok + i + 1)->start, NULL, 0);
            i++;
        } else if (jsoneq(buf, tok + i, "version") == 0) {
            g_version = strtol(buf + (tok + i + 1)->start, NULL, 0);
            i++;
        } else if (jsoneq(buf, tok + i, "blocksize") == 0) {
            g_block_size = strtol(buf + (tok + i + 1)->start, NULL, 0);
            i++;
        } else if (jsoneq(buf, tok + i, "metadata") == 0) {
            i++;
            int end = (tok + i)->end;
            size_t len = (tok + i)->end - (tok + i)->start;
            g_metadata = malloc(len + 1);
            die_if(!g_metadata, ESTR_MALLOC);
            g_metadata[len] = 0;
            g_metadata = memcpy(g_metadata, buf + (tok + i)->start, len);
            BACKY_LOG("metadata: %s\n", g_metadata);
            while ((tok + i + 1)->start < end) i++;
        } else if (jsoneq(buf, tok + i, "hash") == 0) {
            i++;
            vdie_if_n((tok + i)->end - (tok + i)->start != strlen(DEDUP_MAC_NAME) || strncmp(DEDUP_MAC_NAME, buf + (tok + i)->start, strlen(DEDUP_MAC_NAME)), "unsupported hash: '%.*s'\n", (tok + i)->end - (tok + i)->start, buf + (tok + i)->start);
        } else if (jsoneq(buf, tok + i, "crc32c") == 0) {
            g_crc32c_expected = (hex2dec(buf[(tok + i + 1)->start + 0]) << 28) +
                              (hex2dec(buf[(tok + i + 1)->start + 1]) << 24) +
                              (hex2dec(buf[(tok + i + 1)->start + 2]) << 20) +
                              (hex2dec(buf[(tok + i + 1)->start + 3]) << 16) +
                              (hex2dec(buf[(tok + i + 1)->start + 4]) << 12) +
                              (hex2dec(buf[(tok + i + 1)->start + 5]) << 8) +
                              (hex2dec(buf[(tok + i + 1)->start + 6]) << 4) +
                              (hex2dec(buf[(tok + i + 1)->start + 7]) << 0);
            BACKY_LOG("g_crc32c_expected: %08x\n", g_crc32c_expected);
            i += 1;
        } else if (jsoneq(buf, tok + i, "mapping") == 0) {
            vdie_if_n((tok + i + 1)->type != JSMN_OBJECT, "json parser error: mapping has unexpected type (%d)\n", (tok + i + 1)->type);
            g_block_count = (tok + i + 1)->size;
            i+=2;
            die_if(g_block_mapping, ESTR_MALLOC);
            g_block_mapping = malloc((DEDUP_MAC_SIZE_BYTES) * g_block_count);
            die_if(!g_block_mapping, ESTR_MALLOC);
            g_block_is_compressed = malloc(g_block_count);
            die_if(!g_block_is_compressed, ESTR_MALLOC);
            for (j = i; j < i + g_block_count * 2; j += 2) {
                unsigned long seq = strtol(buf + (tok + j)->start, NULL, 0);
                vdie_if_n(seq != (j - i) / 2, "json parser error: invalid sequence in mapping: expected %lu found %lu\n", (j - i) / 2, seq);
                vdie_if_n((tok + j +1)->end - (tok + j +1)->start != DEDUP_MAC_SIZE / 4, "json parser error: invalid mac size in mapping: expected %d found %d\n", DEDUP_MAC_SIZE / 4, (tok + j +1)->end - (tok + j +1)->start);
                for (k = 0; k < DEDUP_MAC_SIZE_BYTES; k++) {
                    g_block_mapping[seq * DEDUP_MAC_SIZE_BYTES + k] = (hex2dec(buf[(tok + j + 1)->start + k * 2]) << 4) +
                                                                    hex2dec(buf[(tok + j + 1)->start + k * 2 + 1]);
                }
            }
            i = j - 1;
        } else {
            if ((tok + i)->type == JSMN_STRING) { 
                vdie_if_n(1, "json parser error: unexpected token '%.*s'\n", (tok + i)->end - (tok + i)->start, buf + (tok + i)->start);
            } else {
                vdie_if_n(1, "json parser error: unexpected token (type %d)\n", (tok + i)->type);
            }
        }
    }

    vdie_if_n(g_version < 1 || g_version > 2, "unsupported version %d\n", g_version);
    vdie_if_n(g_version == 1 && g_block_size != 4096*1024, "unsupported version 1 block size %lu\n", g_block_size);
    vdie_if_n(g_block_size % MIN_CBLK_SIZE || g_block_size < MIN_CBLK_SIZE || g_block_size > MAX_CBLK_SIZE, "unsupported block size %lu\n", g_block_size);

    BACKY_LOG("version: %d\n", g_version);
    BACKY_LOG("blocksize: %u\n", g_block_size);
    BACKY_LOG("size: %lu\n", g_filesize);

    vdie_if_n(g_block_count != (g_filesize + g_block_size - 1) / (g_block_size), "invalid number of chunks: expected %lu found %lu\n", (g_filesize + g_block_size - 1) / (g_block_size), g_block_count);

    BACKY_LOG("blockcount: %lu\n", g_block_count);

    free(tok);
    free(buf);
    fclose(input);
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
