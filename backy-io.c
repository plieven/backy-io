/*
 * back-io - (c) 2017 by Peter Lieven <pl@kamp.de>
 * 
 * partly based on tamp - Threaded fast compressor/decompressor
 * Copyright (c) Tim Cook, 2008.
 *
 * backy-io is free software.  You may redistribute and/or modify it under the
 * terms of the GNU General Public License Version 2, as published by the
 * Free Software Foundation, and available at
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
 *
 * This program is distributed and is to be used with the knowledge that
 * EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR
 * OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/fcntl.h>
#include <utime.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <pthread.h>

#include "jsmn/jsmn.h"

#include <stdint.h>
#include <malloc.h>     /* valloc() */

#define CBLK_SIZE           (4*1024*1024)  /* Default block size - 4096KB */
#define MIN_CBLK_SIZE       (64*1024)     /* 256KByte */
#define MAX_CBLK_SIZE       (16*1024*1024) /* 16MiB */
#define MAX_OUTPUT_BUFFERS  64

#include "smhasher/src/MurmurHash3.h"
#define DEDUP_MAC_NAME "mmh3-x64-128"
#define DEDUP_MAC_SIZE 128
#define DEDUP_HASH_FILENAME_MAX 512
#define mmh3 _Z19MurmurHash3_x64_128PKvijPv

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

pthread_mutex_t log_mutex;

#define TAMP_LOG(format, args...) \
    do { \
        pthread_mutex_lock(&log_mutex); \
        fprintf(stderr, format, ## args); \
        fflush(stderr); \
        pthread_mutex_unlock(&log_mutex); \
    } while (0)

#include "minilzo/minilzo.h"
#define COMPRESS_OVERHEAD   g_block_size / 64 + 16 + 3

static uint32_t crc32c = 0xffffffff;
static uint32_t crc32c_expected = 0xffffffff;

#define plural(n)   ((n) == 1 ? "" : "s")

#ifndef NDEBUG
#define Tdebug(fmt, ...)    (void) fprintf(stderr, fmt, __VA_ARGS__)
#define Tdebug1(fmt, ...)
#define Tdebug2(fmt, ...)
#else
#define Tdebug(...)
#define Tdebug1(...)
#define Tdebug2(...)
#endif

#define dump_q(bufq)

/*
 * Strings used with die_if(), etc.
 */
static char g_estr_mutex_init[] =   "mutex_init";
#define ESTR_MUTEX_INIT         g_estr_mutex_init
static char g_estr_cond_init[] =    "cond_init";
#define ESTR_COND_INIT          g_estr_cond_init
static char g_estr_cond_signal[] =  "cond_signal";
#define ESTR_COND_SIGNAL        g_estr_cond_signal
static char g_estr_cond_wait[] =    "cond_wait";
#define ESTR_COND_WAIT          g_estr_cond_wait
static char g_estr_cond_broadcast[] =   "cond_broadcast";
#define ESTR_COND_BROADCAST     g_estr_cond_broadcast
static char g_estr_mutex_lock[] =   "mutex_lock";
#define ESTR_MUTEX_LOCK         g_estr_mutex_lock
static char g_estr_mutex_unlock[] = "mutex_unlock";
#define ESTR_MUTEX_UNLOCK       g_estr_mutex_unlock
static char g_estr_thread_create[] =    "thread_create";
#define ESTR_THREAD_CREATE      g_estr_thread_create
static char g_estr_thread_attr_init[] = "thread_attr_init";
#define ESTR_THREAD_ATTR_INIT       g_estr_thread_attr_init
static char g_estr_thread_detached[] =  "thread_detached";
#define ESTR_THREAD_DETACHED        g_estr_thread_detached
static char g_estr_thread_join[] =  "thread_join";
#define ESTR_THREAD_JOIN        g_estr_thread_join
static char g_estr_malloc[] =       "malloc";
#define ESTR_MALLOC         g_estr_malloc
static char g_estr_memalign[] =     "memalign";
#define ESTR_MEMALIGN           g_estr_memalign
static char g_estr_write[] =        "write";
#define ESTR_WRITE          g_estr_write
static char g_estr_read[] =     "read";
#define ESTR_READ           g_estr_read
static char g_estr_fdopen[] =       "fdopen";
#define ESTR_FDOPEN         g_estr_fdopen
static char g_estr_fread[] =        "fread";
#define ESTR_FREAD          g_estr_fread


/* ======================================================================== */

/*
 * Volatile int
 */
typedef struct vol_int {
    int value;
    pthread_mutex_t mtx;
} vol_int;

/*
 * volatile buffers
 */

typedef union {
    unsigned long val;
    unsigned char bytes[4];
} ulong_4char;

typedef struct vol_buf {
    struct vol_buf *next;       /* Next in the queue */
    u_int64_t bytes;        /* How big is the buffer */
    u_int64_t seq;      /* Sequence number */
    uint8_t dedup_exists;
    uint8_t is_compressed;
    char hash[DEDUP_MAC_SIZE/8];
    u_int8_t _align[7];
    ulong_4char length;     /* How much is used */
    unsigned char buf[MIN_CBLK_SIZE];   /* the storage - may be more */
} vol_buf;

/*
 * Queue (linked list) of buffers
 */
typedef struct vol_buf_q {
    vol_buf *first;
    vol_buf *last;
    unsigned long last_block;
    unsigned long buffers;
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    unsigned int block_size;
} vol_buf_q;

#define WAIT    1
#define NOWAIT  0

/* ======================================================================== */

static vol_buf_q in_q_free;     /* Used for reading in data */
static vol_buf_q in_q_dirty;    /* Containing data to be processed */
static vol_buf_q comp_q_free;   /* Used for output of compress/decompress */
static vol_buf_q comp_q_dirty;  /* Containing data to be output */

#ifndef NDEBUG
static vol_int in_q_alloc;  /* Buffers allocated for input */
static vol_int comp_q_alloc;    /* Buffers allocated for (de)compression */
#endif

static char *g_arg0;        /* Program name */
static char *g_in_path = NULL;      /* Input file */
static char *g_out_path = NULL; /* Output file */
static char *g_chunk_dir = NULL;   /* directory with dedup tables */

static int g_write_fd;      /* File descriptor to output to */

static volatile uint64_t g_in_bytes = 0;        /* Bytes read */
static volatile uint64_t g_out_bytes = 0;   /* Bytes written */

static int g_opt_verbose    = 0;        /* Verbose flag is set */
static int g_opt_decompress = 0;    /* Decompress is set */
static int g_opt_compress   = 0;        /* Compress is set */
static int g_opt_update     = 0;        /* Update is set */
static int g_opt_verify     = 0;        /* Verify is set */
static int g_opt_verify_simple     = 0;     /* Verify simple is set */
static int g_opt_verify_decompressed     = 0;       /* Verify of decompressed chunks is set */

static vol_int g_compress_threads;
static vol_int g_comp_idle;         /* Zero IFF all (de)compress threads */
                                    /* are busy processing */
static vol_int g_output_buffers;    /* Buffers to be output */
static vol_int g_comp_buffers;      /* Buffers to be (de)compressed */

static unsigned long g_max_threads; /* Maximum (de)compress threads */
static unsigned long g_min_threads = 1; /* Minimum (de)compress threads */

static char *g_stats_path = "(stdin)";
static void *g_zeroblock = NULL;

/* defaults */
static unsigned int g_block_size = CBLK_SIZE;
static unsigned int g_version = 1;
static uint64_t g_filesize = 0;     /* size of the uncompressed data */
static uint64_t g_block_count = 0;
static char* g_block_mapping = NULL;
static uint8_t* g_block_is_compressed = NULL;
static char g_zeroblock_hash[DEDUP_MAC_SIZE/8];

static unsigned int g_opt_dedup = 1;

/* ======================================================================== */

#include <smmintrin.h>
/**
 * Hardware-accelerated CRC32C calculation using the 64-bit instructions.
 */
uint32_t crc32c_hardware(uint32_t crc, const uint8_t* p_buf, size_t length) {
  // start directly at p_buf, even if it's an unaligned address. According
  // to the original author of this code, doing a small run of single bytes
  // to word-align the 64-bit instructions doesn't seem to help, but
  // we haven't reconfirmed those benchmarks ourselves.
  uint64_t crc64bit = crc;
  size_t i;
  for (i = 0; i < length / sizeof(uint64_t); i++) {
    crc64bit = _mm_crc32_u64(crc64bit, *(uint64_t*) p_buf);
    p_buf += sizeof(uint64_t);
  }

  // This ugly switch is slightly faster for short strings than the straightforward loop
  uint32_t crc32bit = (uint32_t) crc64bit;
  length &= sizeof(uint64_t) - 1;
  switch (length) {
    case 7:
      crc32bit = _mm_crc32_u8(crc32bit, *p_buf++);
    case 6:
      crc32bit = _mm_crc32_u16(crc32bit, *(uint16_t*) p_buf);
      p_buf += 2;
    // case 5 is below: 4 + 1
    case 4:
      crc32bit = _mm_crc32_u32(crc32bit, *(uint32_t*) p_buf);
      break;
    case 3:
      crc32bit = _mm_crc32_u8(crc32bit, *p_buf++);
    case 2:
      crc32bit = _mm_crc32_u16(crc32bit, *(uint16_t*) p_buf);
      break;
    case 5:
      crc32bit = _mm_crc32_u32(crc32bit, *(uint32_t*) p_buf);
      p_buf += 4;
    case 1:
      crc32bit = _mm_crc32_u8(crc32bit, *p_buf);
      break;
    case 0:
      break;
    default:
      // This should never happen; enable in debug code
      assert(0 && "ended up with 8 or more bytes at tail of calculation");
  }

  return crc32bit;
}

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

#define die_if(cond, str)   { \
    if (cond) { \
        diag(errno, str); exit(1); } }
#define vdie_if(cond, str, ...) { \
    if (cond) { \
        diag(errno, str, __VA_ARGS__); exit(1); } }
#define vdie_if_n(cond, str, ...) { \
    if (cond) { \
        diag(DIAG_NOT_ERRNO, str, __VA_ARGS__); exit(1); } }

/* Thread calls return 0 if OK, or an error */
#define thr_die_iferr(stat, str) { \
    int ret = (stat); \
    if (ret != 0) { \
        diag(ret, str); exit(1); } }
#define vthr_die_iferr(stat, str, ...) { \
    int ret = (stat); \
    if (ret != 0) { \
        diag(ret, str, __VA_ARGS__); exit(1); }


/* ======================================================================== */

static void
vol_int_init(vol_int *vi)
{
    vi->value = 0;
    die_if(pthread_mutex_init(&(vi->mtx), NULL) != 0,
        ESTR_MUTEX_INIT);
}

static int
increment(vol_int *vi)
{
    int val;

    die_if(pthread_mutex_lock(&(vi->mtx)) != 0, ESTR_MUTEX_LOCK);
    vi->value++;
    val = vi->value;
    die_if(pthread_mutex_unlock(&(vi->mtx)) != 0, ESTR_MUTEX_UNLOCK);
    return (val);
}

static int
decrement(vol_int *vi)
{
    int val;

    die_if(pthread_mutex_lock(&(vi->mtx)) != 0, ESTR_MUTEX_LOCK);
    vi->value--;
    val = vi->value;
    die_if(pthread_mutex_unlock(&(vi->mtx)) != 0, ESTR_MUTEX_UNLOCK);
    return (val);
}

#ifndef NDEBUG
static int
vol_int_get(vol_int *vi)
{
    int val;

    die_if(pthread_mutex_lock(&(vi->mtx)) != 0, ESTR_MUTEX_LOCK);
    val = vi->value;
    die_if(pthread_mutex_unlock(&(vi->mtx)) != 0, ESTR_MUTEX_UNLOCK);
    return (val);
}

static int
vol_int_set(vol_int *vi, int newval)
{
    int val;

    die_if(pthread_mutex_lock(&(vi->mtx)) != 0, ESTR_MUTEX_LOCK);
    val = vi->value;
    vi->value = newval;
    die_if(pthread_mutex_unlock(&(vi->mtx)) != 0, ESTR_MUTEX_UNLOCK);
    return (val);
}
#endif /* NDEBUG */

/* ======================================================================== */

int file_exists(u_int8_t * filename)
{
    int fd;
    if (g_opt_verbose >2) TAMP_LOG("checking for '%s'... ",filename);
    if ((fd = open(filename, O_RDONLY))>0)
    {
        close(fd);
        if (g_opt_verbose >2) TAMP_LOG(" FOUND!\n");
        return 1;
    }
    if (g_opt_verbose >2) TAMP_LOG(" NOT FOUND!\n");
    return 0;
}

int dedup_mkdir(u_int8_t * dir) {
      int ret;
      ret = mkdir(dir, 0755) ? errno : 0;
      vdie_if((ret && (ret != EEXIST)), "mkdir: %s", dir);
      if (g_opt_verbose && !ret) {
          TAMP_LOG("mkdir: %s\n", dir);
      }
      return ret;
}

void dedup_hash_mkdir(u_int8_t * hash)
{
      u_int8_t dir[DEDUP_HASH_FILENAME_MAX];
      snprintf(dir,DEDUP_HASH_FILENAME_MAX,"%s/%02x",g_chunk_dir,hash[0]);
      dedup_mkdir(dir);
      snprintf(dir,DEDUP_HASH_FILENAME_MAX,"%s/%02x/%02x",g_chunk_dir,hash[0],hash[1]);
      dedup_mkdir(dir);
}

static int dedup_hash_sprint(u_int8_t *hash, uint8_t *s) {
    int i;
    for (i=0; i < DEDUP_MAC_SIZE / 8; i++) {
        sprintf(s + i * 2, "%02x", hash[i]);
    }
}

void dedup_hash_filename(u_int8_t * filename, u_int8_t * hash, int compressed)
{
    int i;
    snprintf(filename,DEDUP_HASH_FILENAME_MAX, "%s/%02x/%02x/", g_chunk_dir, hash[0], hash[1]);
    for (i=0; i < DEDUP_MAC_SIZE / 8;i++) {
        sprintf(filename + i * 2 + strlen(g_chunk_dir) + 2 * 3 + 1, "%02x", hash[i]);
    }
    sprintf(filename + i * 2 + strlen(g_chunk_dir) + 2 * 3 + 1, compressed ? ".chunk.lzo" : ".chunk");
}

static vol_buf *
vol_buf_new(unsigned long bytes)
{
    vol_buf *vb;

    /*
     * FYI - we do not allocate the static size for the "buf" field,
     * but instead allocate enough storage for "buf" to hold the
     * number of bytes requested
     */
    vb = (vol_buf *)memalign(4, sizeof (vol_buf) - MIN_CBLK_SIZE + bytes);
    die_if(vb == (vol_buf *)NULL, ESTR_MEMALIGN);
    vb->bytes = bytes;
    vb->length.val = 0;
    vb->next = (vol_buf *)NULL;
    Tdebug1("+  %d: vol_buf_new(%ld) = %x\n", pthread_self(), bytes, vb);
    return (vb);
}

/* NOTE: mutex not locked */
static void
vol_buf_q_zero(vol_buf_q *bufq)
{
    bufq->buffers = 0;
    bufq->last_block = 0;
    bufq->first = NULL;
    bufq->last = NULL;
}

/* NOTE: mutex not locked */
static void
vol_buf_q_init(vol_buf_q *bufq, unsigned int block_size)
{
    Tdebug1("+  %d: vol_buf_q_init(%x, %d)\n", pthread_self(), bufq,
        block_size);
    vol_buf_q_zero(bufq);
    bufq->block_size = block_size;
    die_if(pthread_mutex_init(&(bufq->mtx), NULL) != 0,
        ESTR_MUTEX_INIT);
    die_if(pthread_cond_init(&(bufq->cv), NULL) != 0,
        ESTR_COND_INIT);
}

/*
 * vol_buf_q_reinit -   Re-initialize a vol_buf_q
 *
 * A vol_buf_q needs re-initialization if it was last initialized
 * with a smaller block size.
 */
static void
vol_buf_q_reinit(vol_buf_q *bufq, unsigned int block_size)
{
    die_if(pthread_mutex_lock(&(bufq->mtx)) != 0, ESTR_MUTEX_LOCK);
    if (! bufq->first) {
        /* We have no buffers */
        assert(bufq->buffers == 0);
        /* assert(bufq->last == (vol_buf *)NULL); */
        bufq->block_size = block_size;
        die_if(pthread_mutex_unlock(&(bufq->mtx)) != 0,
            ESTR_MUTEX_UNLOCK);
        return;
    }
    assert(bufq->last != (vol_buf *)NULL);
    assert(bufq->buffers != 0);
    if (bufq->block_size < block_size || !block_size) {
        /* Need re-initialization */
        /* First, free any existing vol_buf's */
        vol_buf *f, *n;
        for (f = bufq->first; f != (vol_buf *)NULL; ) {
            n = f->next;
            free(f);
            f = n;
        }
        /* Then zero everything */
        vol_buf_q_zero(bufq);
        bufq->block_size = block_size;
    } else {
        /* Buffers we already have should be OK */
        bufq->last_block = 0;
    }
    die_if(pthread_mutex_unlock(&(bufq->mtx)) != 0, ESTR_MUTEX_UNLOCK);
}

/*
 * Get first buffer you can find, wait if requested
 */
static vol_buf *
get_first(vol_buf_q *bufq, int wait)
{
    vol_buf *ret = (vol_buf *)NULL;

    Tdebug1("+  %d: get_first(%x, WAIT=%d)\n", pthread_self(), bufq, wait);
    die_if(pthread_mutex_lock(&(bufq->mtx)) != 0, ESTR_MUTEX_LOCK);

    dump_q(bufq);

    if (bufq->first) {
        ret = bufq->first;
        bufq->first = ret->next;
        ret->next = (vol_buf *)NULL;
        bufq->buffers--;
    } else if (wait) {
        /*CONSTCOND*/
        while (1) {
            /* No buffers */
            if (bufq->last_block > 0)
                /* ... and no more will be added */
                break;

            /* Wait on the cond var */
            Tdebug1("+  %d: get_first(%x) -> waiting,"
                " first=%x...\n", pthread_self(), bufq,
                bufq->first);
            die_if(pthread_cond_wait(&(bufq->cv),
                &(bufq->mtx)) != 0, ESTR_COND_WAIT);
            Tdebug1(" + %d: get_first(%x) -> waited, first=%x\n",
                pthread_self(), bufq, bufq->first);
            if (bufq->first) {
                /* Found one */
                ret = bufq->first;
                bufq->first = ret->next;
                ret->next = (vol_buf *)NULL;
                assert(bufq->buffers > 0);
                bufq->buffers--;
                break;
            }
        }
    }
    Tdebug1(" + %d: get_first(%x) [RETURN = %x] buffers=%d\n",
        pthread_self(), bufq, ret, bufq->buffers);
    dump_q(bufq);

    die_if(pthread_mutex_unlock(&(bufq->mtx)) != 0, ESTR_MUTEX_UNLOCK);
    return (ret);
}

#ifndef NDEBUG
static unsigned long
buffer_count(vol_buf_q *bufq)
{
    unsigned long n = 0;
    vol_buf *bufp;

    bufp = bufq->first;
    while (bufp) {
        n++;
        bufp = bufp->next;
    }
    return (n);
}
#endif

/*
 * Get buffer with a specific sequence number, wait if needed
 */
static vol_buf *
get_seq(vol_buf_q *bufq, unsigned long seq)
{
    vol_buf *ret;
    vol_buf *bufp;
    vol_buf *prev;

    Tdebug1("+  %d: get_seq(%x, seq=%ld)\n", pthread_self(), bufq, seq);
    die_if(pthread_mutex_lock(&(bufq->mtx)) != 0, ESTR_MUTEX_LOCK);

    dump_q(bufq);
    ret = (vol_buf *)NULL;

loop_enter:
    bufp = bufq->first;
    Tdebug1("  +%d: get_seq -> bufp=%x\n", pthread_self(), bufp);
    prev = (vol_buf *)NULL;

loop_next:
    if (! bufp) {
        /* Need to wait? */
        if (bufq->last_block != 0 &&
            seq > bufq->last_block) {
            /* We have already gone past last block */
            goto loop_exit;
        } else {
            /* Wait for more */
            Tdebug1(" + %d: get_seq(%x) -> waiting, %x\n",
                pthread_self(), bufq, bufq->first);
            die_if(pthread_cond_wait(&(bufq->cv),
                &(bufq->mtx)) != 0, ESTR_COND_WAIT);
            Tdebug1(" + %d: get_seq(%x) -> waited, %x\n",
                pthread_self(), bufq, bufq->first);
            /* Start at the beginning */
            goto loop_enter;
        }
    }

    if (bufp->seq == seq) {
        /* This is the one we want */
        ret = bufp;
        if (bufq->first == ret)
            /* Taking the first buffer */
            bufq->first = ret->next;
        else
            /* Restore next */
            /*LINTED*/
            prev->next = bufp->next;
        if (bufq->last == ret) {
            /* We are taking the last buffer */
            bufq->last = prev;
            if (prev)
                /* Restore next */
                prev->next = ret->next;
        }
        /* Clean up buffer we will return */
        ret->next = (vol_buf *)NULL;
        assert(bufq->buffers > 0);
        bufq->buffers--;
        goto loop_exit;
    }

    /* No match - go to the next buffer */
    Tdebug1("  +%d: get_seq -> seq=%ld, next=%x\n",
        pthread_self(), bufp->seq, bufp->next);
    prev = bufp;
    bufp = bufp->next;
    goto loop_next;
loop_exit:

    assert(bufq->buffers == buffer_count(bufq));

    dump_q(bufq);

    die_if(pthread_mutex_unlock(&(bufq->mtx)) != 0, ESTR_MUTEX_UNLOCK);
    if (! ret)
        assert(bufq->last_block != 0 && seq > bufq->last_block);
    Tdebug1(" + %d: get_seq[RETURN = %x]\n", pthread_self(), ret);
    return (ret);
}

#ifndef NDEBUG
static vol_buf *
get_last(vol_buf_q *bufq)
{
    vol_buf *ret;

    ret = bufq->first;
    while (ret->next)
        ret = ret->next;
    return (ret);
}
#endif /* NDEBUG */

/*
 * Put a buffer on the end of the queue
 */
static void
put_last(vol_buf_q *bufq, vol_buf *bufp)
{
    vol_buf *p;

    Tdebug1("+  %d: put_last(%x, %x, seq=%ld)\n",
        pthread_self(), bufq, bufp, bufp->seq);
    assert(bufq != (vol_buf_q *)NULL);
    bufp->next = (vol_buf *)NULL;   /* Safety */
    die_if(pthread_mutex_lock(&(bufq->mtx)) != 0, ESTR_MUTEX_LOCK);

    dump_q(bufq);

    if (bufq->first) {
        assert(bufq->last != (vol_buf *)NULL);
        assert(bufq->last->next == (vol_buf *)NULL);
        assert(bufq->last == get_last(bufq));
        p = bufq->last;
        p->next = bufp;
        bufq->last = bufp;
        assert(bufq->last->next == (vol_buf *)NULL);
        assert(bufq->last == get_last(bufq));
    } else {
        /* Nothing on the queue */
        bufq->first = bufp;
        bufq->last = bufp;
    }
    assert(bufq->first != NULL);
    bufq->buffers++;

    dump_q(bufq);

#ifdef NOTDEF
    assert(bufq->buffers == buffer_count(bufq));
#endif
    die_if(pthread_cond_signal(&(bufq->cv)) != 0, ESTR_COND_SIGNAL);
    Tdebug1(" + %d: put_last(%x)->pthread_cond_signal-led, buffers=%d\n",
        pthread_self(), bufq, bufq->buffers);
    die_if(pthread_mutex_unlock(&(bufq->mtx)) != 0, ESTR_MUTEX_UNLOCK);
}

static void
set_last_block(vol_buf_q *bufq, unsigned long seq)
{
    Tdebug1("+  %d: set_last_block(%x, %d)\n", pthread_self(), bufq, seq);
    die_if(pthread_mutex_lock(&(bufq->mtx)) != 0, ESTR_MUTEX_LOCK);
    bufq->last_block = seq;
    die_if(pthread_mutex_unlock(&(bufq->mtx)) != 0, ESTR_MUTEX_UNLOCK);
}


/*
 * Wake up any threads waiting on the queue - used when no more buffers
 * will be put
 */
static void
wakeup(vol_buf_q *bufq)
{
    Tdebug1("+  %d: wakeup(%x)\n", pthread_self(), bufq);
    die_if(pthread_mutex_lock(&(bufq->mtx)) != 0, ESTR_MUTEX_LOCK);
    if (!g_opt_update) assert(bufq->last_block != 0);
    die_if(pthread_cond_broadcast(&(bufq->cv)) != 0,
        ESTR_COND_BROADCAST);
    die_if(pthread_mutex_unlock(&(bufq->mtx)) != 0,
        ESTR_MUTEX_UNLOCK);
}

void init_zero_block() {
    uint8_t h[DEDUP_MAC_SIZE / 4 + 1];
    if (g_zeroblock) return;
    g_zeroblock = valloc(g_block_size);
    die_if(!g_zeroblock, ESTR_MALLOC);
    memset(g_zeroblock, 0x00, g_block_size);
    mmh3(g_zeroblock, g_block_size, 0, &g_zeroblock_hash[0]);
    dedup_hash_sprint(g_zeroblock_hash, h);
    TAMP_LOG("init_zero_block: zeroblock hash is %s\n", h);
}

static int dedup_is_zero_chunk(u_int8_t *hash) {
    if (!g_zeroblock) init_zero_block();
    return !memcmp(hash, g_zeroblock_hash, DEDUP_MAC_SIZE / 8);
}

/* ======================================================================== */

static void *
write_compressed(void *arg)
{
    unsigned long seq;
    unsigned long length;
    vol_buf *bufp;
    int dedup_new=0;
    int dedup_new_comp=0;
    int dedup_existing=0;
    int zeroblocks=0;
    FILE *fp = stdout;
    uint8_t dedup_hash[DEDUP_MAC_SIZE / 4 + 1];

    g_out_bytes = 0;

    if (g_write_fd < 0)
        vdie_if(((fp = fopen(g_out_path, "w")) < 0),
            "fopen: %s", g_out_path);

    fprintf(fp, "{\n");
    fprintf(fp, " \"version\" : %d,\n", g_version);
    fprintf(fp, " \"hash\" : \"%s\",\n", DEDUP_MAC_NAME);
    fprintf(fp, " \"blocksize\" : %u,\n", g_block_size);
    fprintf(fp, " \"mapping\" : {");

    seq = 0;
    /*CONSTCOND*/
    while (1) {
        if (g_opt_update) {
            if (seq == g_block_count) break;
            if (memcmp(g_zeroblock, g_block_mapping + seq * DEDUP_MAC_SIZE / 8, DEDUP_MAC_SIZE / 8)) {
                dedup_hash_sprint(g_block_mapping + seq * DEDUP_MAC_SIZE / 8, &dedup_hash[0]);
                fprintf(fp, "%s\n  \"%lu\" : \"%s\"", seq ? "," : "", seq, dedup_hash);
                seq++;
                dedup_existing++;
                continue;
            }
        }

        bufp = get_seq(&comp_q_dirty, seq);
        if (! bufp) {
            assert(seq > comp_q_dirty.last_block);
            break;
        }
        (void) decrement(&g_output_buffers);

        length = bufp->length.val;
        if (length > 0) {
            assert(g_version == 1 || length <= g_block_size);

            if (g_opt_verbose > 1) {
                TAMP_LOG("write: seq %lu dedup_exists %d is_compressed %d length %lu\n", bufp->seq, bufp->dedup_exists, bufp->is_compressed, bufp->length.val);
            }
            if (!bufp->dedup_exists) {
                dedup_new++;
                dedup_new_comp+=bufp->is_compressed;
            } else {
                dedup_existing++;
            }

            dedup_hash_sprint(bufp->hash, &dedup_hash[0]);
            fprintf(fp, "%s\n  \"%lu\" : \"%s\"", seq ? "," : "", seq, dedup_hash);

            if (dedup_is_zero_chunk(&bufp->hash[0])) {
                zeroblocks++;
            }

        }

        /* Buffer is now free */
        put_last(&comp_q_free, bufp);

        seq++;
    }

    fprintf(fp, "\n },\n");

    if (crc32c != 0xffffffff) {
        TAMP_LOG("crc32c: %08x\n", crc32c);
        fprintf(fp, " \"crc32c\" : \"%08x\",\n", crc32c);
    }

    TAMP_LOG("size: %lu\n", g_opt_update ? g_filesize : g_in_bytes);
    fprintf(fp, " \"size\" : %lu\n", g_opt_update ? g_filesize : g_in_bytes);
    fprintf(fp, "}\n");
    fclose(fp);

    TAMP_LOG("dedup: new %d new_compressed %d existing %d zeroblocks %d\n", dedup_new, dedup_new_comp, dedup_existing, zeroblocks);

    return (NULL);
}
//~ //~

/*
 * compress() - Runs as thread(s) started via pthread_create()
 */
static void *
compress(void *arg)
{
    vol_buf *bufp;
    vol_buf *comp_bufp;
    vol_buf *write_buf;
    unsigned long sequence;
    char *work_buf;
#ifndef NDEBUG
    int blocks_compressed = 0;
#endif

    (void) increment(&g_compress_threads);
    /* Need to initialise work_buf */
    work_buf = valloc(LZO1X_1_MEM_COMPRESS);
    die_if(! work_buf, ESTR_MEMALIGN);

    /*CONSTCOND*/
    while (1) {
        /* Get an output buffer */

        comp_bufp = get_first(&comp_q_free, NOWAIT);
        if (! comp_bufp) {
            /* THROTTLE: Wait if output queue is "full" */
            if (g_output_buffers.value >= MAX_OUTPUT_BUFFERS)
                /* Allow them to drain */
                comp_bufp = get_first(&comp_q_free, WAIT);
            else {
                /* Get a new buffer */
                comp_bufp = vol_buf_new(g_block_size +
                    COMPRESS_OVERHEAD);
#ifndef NDEBUG
                (void) increment(&comp_q_alloc);
#endif
            }
        }
        assert(comp_bufp);
        (void) increment(&g_output_buffers);

        /* Get a buffer to compress */
        bufp = get_first(&in_q_dirty, WAIT);
        if (! bufp) {
            /* No more work to do */
            /* No longer need output buffer, so put it back */
            put_last(&comp_q_free, comp_bufp);
            break;
        }

        /* Compress */
        (void) decrement(&g_comp_idle);
        
        comp_bufp->dedup_exists = bufp->dedup_exists = 0;
        comp_bufp->is_compressed = bufp->is_compressed = 0;

        if (bufp->length.val > 0) {
            uint8_t dedup_filename[DEDUP_HASH_FILENAME_MAX];
            mmh3(&(bufp->buf), bufp->length.val, 0, &bufp->hash[0]);
            dedup_hash_filename(dedup_filename, &bufp->hash[0], 1);
            comp_bufp->dedup_exists = bufp->dedup_exists = file_exists(dedup_filename);
            comp_bufp->is_compressed = 1;
            if (!bufp->dedup_exists && g_version > 1) {
                dedup_hash_filename(dedup_filename, &bufp->hash[0], 0);
                comp_bufp->dedup_exists = bufp->dedup_exists = file_exists(dedup_filename);
                comp_bufp->is_compressed = 0;
            }

            if (!bufp->dedup_exists)
             {
            (void) lzo1x_1_compress(
                (unsigned char *) &(bufp->buf),
                bufp->length.val,
                (unsigned char *) &(comp_bufp->buf) + 5,
                (unsigned long *) &(comp_bufp->length),
                work_buf);
                comp_bufp->is_compressed = 1;
                comp_bufp->buf[0] = 0xf0;
                comp_bufp->buf[1] = bufp->length.val >> 24;
                comp_bufp->buf[2] = bufp->length.val >> 16;
                comp_bufp->buf[3] = bufp->length.val >> 8;
                comp_bufp->buf[4] = bufp->length.val;
                comp_bufp->length.val += 5;
            }
       }


        /* Set the sequence number */
        sequence = bufp->seq;
        comp_bufp->seq = sequence;

        /* Did we get negative compression? */
        if (bufp->dedup_exists || !bufp->length.val || 
           (g_version > 1 && comp_bufp->length.val >= g_block_size &&
            bufp->length.val == g_block_size)) {
            /* Yes - write out original block */
            put_last(&in_q_free, comp_bufp);
            write_buf = bufp;
        } else {
            /*
             * No - post the input buffer back to the input
             * thread's free list, and the decompressed buffer
             * on to the queue for the write thread.
             */
            memcpy(&comp_bufp->hash, &bufp->hash, DEDUP_MAC_SIZE / 8);
            put_last(&in_q_free, bufp);
            write_buf = comp_bufp;
        }

#ifndef NDEBUG
        blocks_compressed++;
#endif
        if (!write_buf->dedup_exists) {
            int g_write_fd_dedup;
            ssize_t bytes;
            uint8_t dedup_filename[DEDUP_HASH_FILENAME_MAX];
            dedup_hash_filename(dedup_filename, &write_buf->hash[0], write_buf->is_compressed);
            dedup_hash_mkdir(write_buf->hash);
            g_write_fd_dedup = open(dedup_filename,
              O_WRONLY | O_LARGEFILE | O_CREAT | O_EXCL, 0666);
            if (g_write_fd_dedup < 0) {
                if (errno != EEXIST) {
                    vdie_if(1,"dedup chunk write: %s", dedup_filename);
                }
                TAMP_LOG("dedup write collision: %s\n", dedup_filename);
                write_buf->dedup_exists = 1;
            } else {
                bytes = write(g_write_fd_dedup, &(write_buf->buf), write_buf->length.val);
                close(g_write_fd_dedup);
                if (bytes < 0) {
                    unlink(dedup_filename);
                }
                die_if(bytes < 0, ESTR_WRITE);
            }
        }
        put_last(&comp_q_dirty, write_buf);

        (void) increment(&g_comp_idle);
        (void) decrement(&g_comp_buffers);
    }
    (void) decrement(&g_comp_idle);

    set_last_block(&comp_q_dirty, in_q_dirty.last_block);
    if (in_q_dirty.last_block == sequence)
        wakeup(&comp_q_dirty);
    free(work_buf);

    Tdebug2("+ compress() - return; tid = %d, blocks = %d\n",
        pthread_self, blocks_compressed);
    return (NULL);
}

/*
 * compress_fd -    Compress a stream of bytes
 *
 *  fd  File descriptor, readable
 */

static void
compress_fd(int fd)
{
    unsigned char *readp;
    pthread_t compress_thr;
    pthread_t write_thr;
    pthread_attr_t compress_thr_attr;
    void *wr_status;
    ssize_t bytes, b;
    unsigned long sequence = 0;
    unsigned long i;
    vol_buf *bufp;
    int ret;

    assert(vol_int_get(&g_compress_threads) == 0);
    assert(vol_int_get(&g_comp_idle) == 0);
    assert(vol_int_get(&g_output_buffers) == 0);
    assert(vol_int_get(&g_comp_buffers) == 0);

    /* Initialize LZ01X-1 */
    if ((ret = lzo_init()) != LZO_E_OK) {
        diag(DIAG_NOT_ERRNO, "lzo_init failed (%d)\n", ret);
        exit(1);
    }

    /* Initialize compress thread attributes */
    thr_die_iferr(pthread_attr_init(&compress_thr_attr),
        ESTR_THREAD_ATTR_INIT);
    thr_die_iferr(pthread_attr_setdetachstate(&compress_thr_attr,
        PTHREAD_CREATE_DETACHED), ESTR_THREAD_DETACHED);

    /* Start minimum compress threads */
    for (i = 0; i < g_min_threads; i++) {
        Tdebug2("+ pthread_create(compress) [PRE LOOP]\n", NULL);
        (void) increment(&g_comp_idle);
        thr_die_iferr(pthread_create(&compress_thr, &compress_thr_attr,
            compress, NULL), ESTR_THREAD_CREATE);
    }

    /* Start output thread */
    thr_die_iferr(pthread_create(&write_thr, NULL, write_compressed, NULL),
        ESTR_THREAD_CREATE);

    /*CONSTCOND*/
    while (1) {
        if (g_opt_update) {
            if (sequence == g_block_count) break;
            if (memcmp(g_zeroblock, g_block_mapping + sequence * DEDUP_MAC_SIZE / 8, DEDUP_MAC_SIZE / 8)) {
                sequence++;
                g_in_bytes += g_block_size;
                g_in_bytes = MIN(g_in_bytes, g_filesize);
                continue;
            }
            if (sequence * g_block_size != lseek(fd, sequence * g_block_size, SEEK_SET)) {
                TAMP_LOG("seek error.\n");
                exit(1);
            }
        }
        /* Get a read buffer */
        if (g_comp_buffers.value >= MAX_OUTPUT_BUFFERS) {
            /* Allow buffers to drain */
            bufp = get_first(&in_q_free, WAIT);
        } else {
            /* Try, then get a new buffer */
            bufp = get_first(&in_q_free, NOWAIT);
            if (! bufp) {
                bufp = vol_buf_new(g_block_size +
                    COMPRESS_OVERHEAD);
#ifndef NDEBUG
                (void) increment(&in_q_alloc);
#endif
            }
        }
        (void) increment(&g_comp_buffers);
        assert(bufp);
        readp = (unsigned char *)&(bufp->buf);

        /*
         * Do the read(s) - we need to keep issuing read()'s until
         * we have filled our g_block_size buffer, or got a zero read,
         * as we will get short reads from fifofs.
         */
        bytes = 0;
        while (bytes < g_block_size) {
            int max_read = g_block_size - bytes;
            b = read(fd, readp, max_read);
            if (b == 0)
                /* EOF */
                break;
            die_if(b < 0, ESTR_READ);
            bytes += b;
            readp += b;
        }
        g_in_bytes += (uint64_t)bytes;
        if (!g_opt_update) {
            crc32c=crc32c_hardware(crc32c,(const u_int8_t *) bufp->buf,bytes);
        }
        bufp->length.val = bytes;
        bufp->seq = sequence;

        if (g_opt_verbose) TAMP_LOG("progress: %lu bytes processed.\n", g_in_bytes);

        /* Post the buffer to be compressed */
        put_last(&in_q_dirty, bufp);

        /* THROTTLE: Do we want to start another compress thread? */
        if (g_comp_idle.value < 1 &&
            g_output_buffers.value <= MAX_OUTPUT_BUFFERS &&
            g_compress_threads.value < g_max_threads) {
            Tdebug2("+ pthread_create(compress) %d\n",
                g_comp_idle.value);
            (void) increment(&g_comp_idle);
            thr_die_iferr(pthread_create(&compress_thr, NULL,
                compress, NULL), ESTR_THREAD_CREATE);
        }

        /* Is it the last block? */
        if (bytes < g_block_size) {
            set_last_block(&in_q_dirty, sequence);
            break;
        }

        sequence++;
    }

    /* Wake up any remaining compress threads */
    wakeup(&in_q_dirty);

    /* Wait for the output thread to complete */
    thr_die_iferr(pthread_join(write_thr, &wr_status), ESTR_THREAD_JOIN);

    if (g_opt_verbose) {
        /* Report statistics */
        if (g_out_bytes < g_in_bytes)
            TAMP_LOG(
                "%s: read %llu, wrote %llu (-%3.1f%%),"
                " %d thread%s\n",
                g_stats_path, (unsigned long long)g_in_bytes,
                (unsigned long long)g_out_bytes,
                (double)(g_in_bytes - g_out_bytes)
                / (double)g_in_bytes * 100.0,
                g_compress_threads.value,
                plural(g_compress_threads.value));
        else
            TAMP_LOG(
                "%s: read %llu, wrote %llu (+%.3f%%),"
                " %d thread%s\n",
                g_stats_path, (unsigned long long)g_in_bytes,
                (unsigned long long)g_out_bytes,
                (double)(g_out_bytes - g_in_bytes)
                / (double)g_in_bytes * 100.0,
                g_compress_threads.value,
                plural(g_compress_threads.value));
    }
}

static void *
write_decompressed(void *arg)
{
    unsigned long sequence;
    vol_buf *bufp;

    g_out_bytes = 0;

    if (g_opt_decompress) {
        if (g_write_fd < 0) {
            vdie_if((g_write_fd = open(g_out_path,
                O_WRONLY | O_CREAT | O_LARGEFILE, 0666)) < 0,
                "open: %s", g_out_path);
        } else {
            //write to stdout
            if (fcntl(1, F_SETPIPE_SZ, g_block_size) < 0) {
                TAMP_LOG("WARN: f_setpipe_sz to %d failed\n", g_block_size);
            }
        }
    }

    sequence = 0;
    /*CONSTCOND*/
    while (1) {
        void *buf = g_zeroblock;
        size_t length = g_block_size;
        void *buf_hash = g_block_mapping + sequence * DEDUP_MAC_SIZE / 8;
        uint8_t is_zero_chunk = dedup_is_zero_chunk(buf_hash);
        if (!is_zero_chunk) {
            bufp = get_seq(&comp_q_dirty, sequence);
            if (! bufp) {
                /* We missed g_last_block being set */
                assert(sequence > comp_q_dirty.last_block);
                break;
            }

            length = bufp->length.val;
            assert(MIN(length, g_filesize - g_out_bytes) == length);
            buf = bufp->buf;

            if (g_opt_verify_decompressed) {
                char hash[DEDUP_MAC_SIZE/8];
                char hash_c[DEDUP_MAC_SIZE/4+1];
                char hash_e[DEDUP_MAC_SIZE/4+1];
                mmh3(bufp->buf, length, 0, &hash[0]);
                dedup_hash_sprint(&hash[0], hash_c);
                dedup_hash_sprint(buf_hash, hash_e);
                vdie_if_n(memcmp(&hash[0], buf_hash, DEDUP_MAC_SIZE / 8), "seq %d hash mismatch computed %s expected %s\n", sequence, hash_c, hash_e);
                if (g_opt_verbose > 1) {
                    TAMP_LOG("chunk seq %lu hash %s OK\n", sequence, hash_c);
                }
            }
        }

        if (g_opt_decompress) {
            die_if(write(g_write_fd, buf, length) < 0, ESTR_WRITE);
        }
        g_out_bytes += length;
        crc32c = crc32c_hardware(crc32c,(const u_int8_t *) buf, length);

        if (g_opt_verbose) {
            TAMP_LOG("progress: %lu bytes processed.\n", g_out_bytes);
        }

        if (!is_zero_chunk) {
            /* We can free that buffer */
            put_last(&comp_q_free, bufp);
            (void) decrement(&g_output_buffers);
        }

        sequence++;
    }

    vdie_if_n(g_out_bytes != g_filesize, "out_bytes does not match size (%lu != %lu)\n", g_out_bytes, g_filesize);

    if (g_opt_verify_decompressed) {
        TAMP_LOG("verify_deep: all chunks checksum passed\n");
    }

    if (crc32c_expected != 0xffffffff) {
        vdie_if_n(crc32c != crc32c_expected,"crc32c checksum failure: expected %08x computed %08x\n", crc32c_expected, crc32c);
        TAMP_LOG("crc32c: %08x\n", crc32c);
        TAMP_LOG("verify_crc32: checksum correct\n");
    }

    if (g_opt_decompress) {
        close(g_write_fd);
    }

    return (NULL);
}

static void *
decompress(void *arg)
{
    vol_buf *bufp, *comp_bufp;
    int ret;
#ifndef NDEBUG
    int blocks_compressed = 0;
#endif

    (void) increment(&g_compress_threads);

    /*CONSTCOND*/
    while (1) {
        /* Get an output buffer */
        comp_bufp = get_first(&comp_q_free, NOWAIT);
        if (! comp_bufp) {
            /* THROTTLE: Wait if output queue is "full" */
            if (g_output_buffers.value >= MAX_OUTPUT_BUFFERS)
                /* Allow them to drain */
                comp_bufp = get_first(&comp_q_free, WAIT);
            else {
                /* Get a new buffer */
                comp_bufp = vol_buf_new(g_block_size +
                    COMPRESS_OVERHEAD);
#ifndef NDEBUG
                (void) increment(&comp_q_alloc);
#endif
            }
        }
        assert(comp_bufp);
        (void) increment(&g_output_buffers);

        /* Get a buffer to decompress */
        bufp = get_first(&in_q_dirty, WAIT);
        if (! bufp) {
            /* No more work to do */
            /* No longer need output buffer, so put it back */
            put_last(&comp_q_free, comp_bufp);
            break;
        }

        (void) decrement(&g_comp_idle);
        
        int read_fd_dedup;
        u_int8_t dedup_file[DEDUP_HASH_FILENAME_MAX];
        dedup_hash_filename(dedup_file, g_block_mapping + bufp->seq * DEDUP_MAC_SIZE / 8,
                            g_block_is_compressed[bufp->seq]);
        vdie_if((read_fd_dedup = open(dedup_file,
                O_RDONLY)) < 0,
                "open: %s", dedup_file);
        die_if((bufp->length.val = read(read_fd_dedup,(void *)&(bufp->buf), bufp->bytes)) < 0,ESTR_FREAD);
        close(read_fd_dedup);
        g_in_bytes += bufp->length.val;
        if (g_opt_verbose > 1) {
                  TAMP_LOG("dedup: successfully read %lu bytes from %s\n",bufp->length.val,dedup_file);
        }

        /* Set the sequence number */
        comp_bufp->seq = bufp->seq;

        if (bufp->length.val == g_block_size && g_version > 1) {
            put_last(&in_q_free, comp_bufp);
            put_last(&comp_q_dirty, bufp);
            //XXX: verify if the hash is ok ?!
        } else {
            uint64_t expected_size = MIN(g_block_size, g_filesize - bufp->seq * g_block_size);
            vdie_if_n(bufp->buf[0] != 0xf0 || bufp->length.val < 5 + 3, "lzo header error\n", 0);
            comp_bufp->length.val = (bufp->buf[1] << 24) | (bufp->buf[2] << 16) | (bufp->buf[3] << 8) | bufp->buf[4];
            vdie_if_n(comp_bufp->length.val < 0 || bufp->length.val - 5 > comp_bufp->length.val + comp_bufp->length.val / 64 + 16 + 3, "lzo header error\n", 0);
            vdie_if_n(comp_bufp->length.val != expected_size, "lzo data has unexpected size (expected %lu found %lu)\n", expected_size, comp_bufp->length.val);
            /* Decompress */
            ret = lzo1x_decompress(
                (const unsigned char *) &(bufp->buf) + 5,
                bufp->length.val - 5,
                (unsigned char *) &(comp_bufp->buf),
                (unsigned long *) &(comp_bufp->length),
                NULL);
            if (ret != LZO_E_OK) {
                TAMP_LOG(
                    "%s: lzo1x_decompress failed, "
                "return     = %d\n", g_arg0, ret);
                exit(1);
            }
            /*
             * Now post the input buffer back to the input
             * thread's free list, and the decompressed buffer
             * on to the queue for the write thread.
             */
            put_last(&in_q_free, bufp);
            put_last(&comp_q_dirty, comp_bufp);
        }
#ifndef NDEBUG
        blocks_compressed++;
#endif
        (void) increment(&g_comp_idle);
        (void) decrement(&g_comp_buffers);
    }
    (void) decrement(&g_comp_idle);
    assert(in_q_dirty.last_block != 0);
    set_last_block(&comp_q_dirty, in_q_dirty.last_block);
    wakeup(&comp_q_dirty);

    Tdebug2("+ decompress() - return; tid = %d, blocks = %d\n",
        pthread_self, blocks_compressed);
    return (NULL);
}

#define VBUF_SIZE   65536
#define BUF_SIZE    65536

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
        } else if (jsoneq(buf, tok + i, "hash") == 0) {
            i++;
            vdie_if_n((tok + i)->end - (tok + i)->start != strlen(DEDUP_MAC_NAME) || strncmp(DEDUP_MAC_NAME, buf + (tok + i)->start, strlen(DEDUP_MAC_NAME)), "unsupported hash: '%.*s'\n", (tok + i)->end - (tok + i)->start, buf + (tok + i)->start);
        } else if (jsoneq(buf, tok + i, "crc32c") == 0) {
            crc32c_expected = (hex2dec(buf[(tok + i + 1)->start + 0]) << 28) +
                              (hex2dec(buf[(tok + i + 1)->start + 1]) << 24) +
                              (hex2dec(buf[(tok + i + 1)->start + 2]) << 20) +
                              (hex2dec(buf[(tok + i + 1)->start + 3]) << 16) +
                              (hex2dec(buf[(tok + i + 1)->start + 4]) << 12) +
                              (hex2dec(buf[(tok + i + 1)->start + 5]) << 8) +
                              (hex2dec(buf[(tok + i + 1)->start + 6]) << 4) +
                              (hex2dec(buf[(tok + i + 1)->start + 7]) << 0);
            TAMP_LOG("crc32c_expected: %08x\n", crc32c_expected);
            i += 1;
        } else if (jsoneq(buf, tok + i, "mapping") == 0) {
            vdie_if_n((tok + i + 1)->type != JSMN_OBJECT, "json parser error: mapping has unexpected type (%d)\n", (tok + i + 1)->type);
            g_block_count = (tok + i + 1)->size;
            i+=2;
            die_if(g_block_mapping, ESTR_MALLOC);
            g_block_mapping = malloc((DEDUP_MAC_SIZE / 8) * g_block_count);
            die_if(!g_block_mapping, ESTR_MALLOC);
            g_block_is_compressed = malloc(g_block_count);
            die_if(!g_block_is_compressed, ESTR_MALLOC);
            for (j = i; j < i + g_block_count * 2; j += 2) {
                unsigned long seq = strtol(buf + (tok + j)->start, NULL, 0);
                vdie_if_n(seq != (j - i) / 2, "json parser error: invalid sequence in mapping: expected %lu found %lu\n", (j - i) / 2, seq);
                vdie_if_n((tok + j +1)->end - (tok + j +1)->start != DEDUP_MAC_SIZE / 4, "json parser error: invalid mac size in mapping: expected %d found %d\n", DEDUP_MAC_SIZE / 4, (tok + j +1)->end - (tok + j +1)->start);
                for (k = 0; k < DEDUP_MAC_SIZE / 8; k++) {
                    g_block_mapping[seq * DEDUP_MAC_SIZE / 8 + k] = (hex2dec(buf[(tok + j + 1)->start + k * 2]) << 4) +
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

    TAMP_LOG("version: %d\n", g_version);
    TAMP_LOG("blocksize: %u\n", g_block_size);
    TAMP_LOG("size: %lu\n", g_filesize);

    vdie_if_n(g_block_count != (g_filesize + g_block_size - 1) / (g_block_size), "invalid number of chunks: expected %lu found %lu\n", (g_filesize + g_block_size - 1) / (g_block_size), g_block_count);

    TAMP_LOG("blockcount: %lu\n", g_block_count);

    free(tok);
    free(buf);
    fclose(input);
}

void verify_chunks() {
    u_int8_t chunk_file[DEDUP_HASH_FILENAME_MAX];
    int i;
    for (i = 0; i < g_block_count; i++) {
        uint8_t dedup_exists;
        if (g_version > 1 && dedup_is_zero_chunk(g_block_mapping + i * DEDUP_MAC_SIZE / 8)) continue;
        if (g_opt_update && !memcmp(g_zeroblock, g_block_mapping + i * DEDUP_MAC_SIZE / 8, DEDUP_MAC_SIZE / 8)) continue;
        dedup_hash_filename(chunk_file, g_block_mapping + i * DEDUP_MAC_SIZE / 8, 1);
        dedup_exists = file_exists(chunk_file);
        g_block_is_compressed[i] = 1;
        if (!dedup_exists && g_version > 1) {
            dedup_hash_filename(chunk_file, g_block_mapping + i * DEDUP_MAC_SIZE / 8, 0);
            dedup_exists = file_exists(chunk_file);
            g_block_is_compressed[i] = 0;
        }
        vdie_if_n(!dedup_exists, "verify: chunk %s does not exist\n", chunk_file);
    }
    TAMP_LOG("verify_simple: all chunks available\n");
}

static void
decompress_fd(int fd)
{
    pthread_t decompress_thr;
    pthread_t write_thr;
    pthread_attr_t compress_thr_attr;
    void *wr_status;
    unsigned long i;
    vol_buf *bufp;
    int ret;

    assert(vol_int_get(&g_compress_threads) == 0);
    assert(vol_int_get(&g_comp_idle) == 0);
    assert(vol_int_get(&g_output_buffers) == 0);
    assert(vol_int_get(&g_comp_buffers) == 0);

    /*
     * Re-initialise buffer queues
     */
    vol_buf_q_reinit(&in_q_free, g_block_size);
    vol_buf_q_reinit(&in_q_dirty, g_block_size);
    vol_buf_q_reinit(&comp_q_free, g_block_size);
    vol_buf_q_reinit(&comp_q_dirty, g_block_size);
#ifndef NDEBUG
    if (comp_q_free.buffers == 0)
        (void) vol_int_set(&comp_q_alloc, 0);
    if (in_q_free.buffers == 0)
        (void) vol_int_set(&in_q_alloc, 0);
#endif

    /* Initialize LZ01X-1 */
    if ((ret = lzo_init()) != LZO_E_OK) {
        diag(-1, "lzo_init failed (%d)\n", ret);
        exit(1);
    }

    /* Initialize compress thread attributes */
    thr_die_iferr(pthread_attr_init(&compress_thr_attr),
        ESTR_THREAD_ATTR_INIT);
    thr_die_iferr(pthread_attr_setdetachstate(&compress_thr_attr,
        PTHREAD_CREATE_DETACHED), ESTR_THREAD_DETACHED);

    /* Start minimum decompress threads */
    for (i = 0; i < g_min_threads; i++) {
        Tdebug2("+ pthread_create(decompress) [PRE LOOP]\n", NULL);
        (void) increment(&g_comp_idle);
        thr_die_iferr(pthread_create(&decompress_thr,
            &compress_thr_attr, decompress, NULL),
            ESTR_THREAD_CREATE);
    }

    /* Start output thread */
    thr_die_iferr(pthread_create(&write_thr, NULL,
        write_decompressed, NULL), ESTR_THREAD_CREATE);

    for (i = 0; i < g_block_count; i++) {
        if (dedup_is_zero_chunk(g_block_mapping + i * DEDUP_MAC_SIZE / 8)) {
            continue;
        }
        /* Get a read buffer */
        if (g_comp_buffers.value >= MAX_OUTPUT_BUFFERS) {
            /* Allow buffers to drain */
            bufp = get_first(&in_q_free, WAIT);
        } else {
            /* Try, then get a new buffer */
            bufp = get_first(&in_q_free, NOWAIT);
            if (! bufp) {
                bufp = vol_buf_new(g_block_size +
                    COMPRESS_OVERHEAD);
#ifndef NDEBUG
                (void) increment(&in_q_alloc);
#endif
            }
        }
        assert(bufp);
        (void) increment(&g_comp_buffers);

        bufp->seq = i;

        /* THROTTLE: Start a new decompress thread? */
        if (g_comp_idle.value < 1 &&
            g_output_buffers.value <= MAX_OUTPUT_BUFFERS &&
            g_compress_threads.value < g_max_threads) {
            /* Start a new decompress thread */
            Tdebug2("+ pthread_create(decompress) %d\n",
                g_comp_idle.value);
            (void) increment(&g_comp_idle);
            thr_die_iferr(pthread_create(&decompress_thr, NULL,
                decompress, NULL), ESTR_THREAD_CREATE);
        }
        put_last(&in_q_dirty, bufp);
    }

    set_last_block(&in_q_dirty, i - 1);

    /* Wake up any remaining compress threads */
    wakeup(&in_q_dirty);

    /* Free the buffers */

    /* Wait for the output thread to complete */
    thr_die_iferr(pthread_join(write_thr, &wr_status), ESTR_THREAD_JOIN);

    if (g_opt_verbose == 1)
        /* Report statistics */
        TAMP_LOG(
            "%s: read %llu, wrote %llu, %d thread%s\n",
            g_stats_path, (unsigned long long)g_in_bytes,
            (unsigned long long)g_out_bytes,
            g_compress_threads.value,
            plural(g_compress_threads.value));
    else if (g_opt_verbose > 1)
        TAMP_LOG(
            "%s: read %llu, wrote %llu, %uKB blocks, "
            "%d thread%s\n",
            g_stats_path, (unsigned long long)g_in_bytes,
            (unsigned long long)g_out_bytes,
            g_block_size / 1024,
            g_compress_threads.value,
            plural(g_compress_threads.value));
}

/* ======================================================================== */

int
main(int argc, char **argv)
{
    int read_fd;
    int c;
    int opt_error = 0;
    extern char *optarg;
    extern int optind;
    int errors = 0;

    pthread_mutex_init(&log_mutex, NULL);

    if (g_arg0 = strrchr(argv[0], '/'))
        g_arg0++;
    else
        g_arg0 = argv[0];
    /* Compress or decompress? */
    if (strncmp(g_arg0, "un", 2) == 0)
        g_opt_decompress = 1;

    read_fd = 0;        /* stdin */
    g_write_fd = 1;     /* stdout */

    /* Default maximum threads */
    g_max_threads = sysconf(_SC_NPROCESSORS_ONLN);

    while ((c = getopt(argc, argv, "1VtTdvcui:o:b:p:m:X:")) != -1) {
        switch (c) {
        case '1':
            g_version = 1;
            break;
        case 'V':
            g_opt_verify_decompressed = 1;
            break;
        case 't':
            g_opt_verify = 1;
            break;
        case 'T':
            g_opt_verify_simple = 1;
            break;
        case 'd':
            g_opt_decompress = 1;
            break;
        case 'v':
            g_opt_verbose++;
            break;
        case 'c':
            g_opt_compress = 1;
            g_version = 2;
            break;
        case 'u':
            g_opt_update = 1;
            g_version = 2;
            break;
        case 'i':
            /* Input file specified */
            g_stats_path = optarg;
            g_in_path = optarg;
            vdie_if((read_fd = open(optarg, O_RDONLY | O_LARGEFILE,
                0)) < 0, "open: %s", optarg);
            TAMP_LOG("input: %s\n", optarg);
            break;
        case 'o':
            /* Output file specified */
            g_out_path = optarg;
            g_write_fd = -1;
            break;
        case 'b':
            /* Block size */
            g_block_size = atoi(optarg) * 1024;
            vdie_if_n(g_block_size > MAX_CBLK_SIZE,
                "block size (%s KB) can not exceed %d\n",
                optarg, MAX_CBLK_SIZE / 1024);
            vdie_if_n(g_block_size < MIN_CBLK_SIZE,
                "block size (%s KB) can not be less than %d\n",
                optarg, MIN_CBLK_SIZE / 1024);
            vdie_if_n(g_block_size % MIN_CBLK_SIZE,
                "block size (%s KB) is not a multiple of %d\n",
                optarg, MIN_CBLK_SIZE / 1024);
            break;
        case 'p':
            g_max_threads = atol(optarg);
            break;
        case 'm':
            g_min_threads = atol(optarg);
            break;
        case 'X':
            g_opt_dedup=1;
            g_chunk_dir = strdup(optarg);
            break;
        default:
            opt_error++;
        }
    }

    if (g_opt_compress + g_opt_decompress + g_opt_verify + g_opt_verify_simple + g_opt_update != 1) opt_error++;

    if ((g_opt_compress && !g_out_path) || (!g_opt_compress && !g_in_path)) {
        opt_error++;
    }

    if (g_opt_update && (!g_out_path || !g_in_path)) {
        opt_error++;
    }

    if (g_version == 1 && g_block_size != 4 * 1024 * 1024) {
        opt_error++;
    }

    if (opt_error) {
        TAMP_LOG("operations:\n"
            " DECOMPRESS TO STDOUT: %s -d -i <infile.json> [-v] [-V] [-m minthr] [-p maxthr] [-X chunkdir]\n"
            " DECOMPRESS TO FILE:   %s -d -i <infile.json> -o <outfile.raw> [-v] [-V] [-m minthr] [-p maxthr] [-X chunkdir]\n"
            " COMPRESS FROM STDIN:  %s -c -o <outfile.json> [-v] [-b <blkKB>] [-m minthr] [-p maxthr] [-X chunkdir] [-1]\n"
            " COMPRESS FROM FILE:   %s -c -i <infile.raw> -o <outfile.json> [-v] [-b <blkKB>] [-m minthr] [-p maxthr] [-X chunkdir] [-1]\n"
            " UPDATE FROM FILE:     %s -u -i <infile.raw> -o <outfile.json> [-v] [-b <blkKB>] [-m minthr] [-p maxthr] [-X chunkdir] [-1]\n"
            " VERIFY SIMPLE:        %s -T -i <infile.json> [-v] [-X chunkdir]\n"
            " VERIFY DEEP:          %s -t -i <infile.json> [-v] [-V] [-m minthr] [-p maxthr] [-X chunkdir]\n\n"
            "options: \n"
            " -v verbose (repeat to increase verbosity)\n"
            " -V verify decompressed chunks\n"
            " -1 force write of version 1 backups (blocksize must be 4096kB)\n"
            " -m <num> minimum number of threads\n"
            " -p <num> maximum number of threads\n"
            " -b <num> blocksize in KB (64 kByte to 16 MiB in 64 KiB steps)\n"
            " -X <dir> directory where the chunks are (defauls to chunks/ relative to json-file)\n",
            g_arg0, g_arg0, g_arg0, g_arg0, g_arg0, g_arg0, g_arg0);
        exit(2);
    }

    TAMP_LOG("pid: %d\n",getpid());

    /*
     * Initialise buffer queues
     */
    vol_buf_q_init(&in_q_free, g_block_size);
    vol_buf_q_init(&in_q_dirty, g_block_size);
    vol_buf_q_init(&comp_q_free, g_block_size);
    vol_buf_q_init(&comp_q_dirty, g_block_size);

#ifndef NDEBUG
    vol_int_init(&in_q_alloc);
    vol_int_init(&comp_q_alloc);
#endif
    vol_int_init(&g_compress_threads);
    vol_int_init(&g_comp_idle);
    vol_int_init(&g_output_buffers);
    vol_int_init(&g_comp_buffers);

    if (!read_fd) TAMP_LOG("input: (stdin)\n");
    if (g_opt_decompress || g_opt_compress) TAMP_LOG("output: %s\n", g_write_fd != 1 ? g_out_path : "(stdout)");

    TAMP_LOG("max_threads: %lu\n", g_max_threads);

    if (!g_chunk_dir) {
        g_chunk_dir = strdup((g_opt_compress || g_opt_update) ? g_out_path : g_in_path);
        dirname(g_chunk_dir);
        g_chunk_dir = realloc(g_chunk_dir, strlen(g_chunk_dir) + 8);
        sprintf(g_chunk_dir, "%s/chunks", g_chunk_dir);
    }

    TAMP_LOG("chunkdir: %s\n", g_chunk_dir);

    if (g_opt_update) {
        int write_fd;
        struct stat st;
        vdie_if((write_fd = open(g_out_path, O_RDONLY | O_LARGEFILE,
                0)) < 0, "open: %s", optarg);
        parse_json(write_fd);
        close(write_fd);
        verify_chunks();
        vdie_if(fstat(read_fd, &st) < 0, "fstat failed", 0);
        vdie_if(st.st_size != g_filesize, "input filesize does not match backup filesize (%lu != %lu)", st.st_size, g_filesize);
        compress_fd(read_fd);
    } else if (g_opt_decompress || g_opt_verify || g_opt_verify_simple) {
        parse_json(read_fd);
        verify_chunks();
        if (g_opt_verify_simple) goto out;
        init_zero_block();
        decompress_fd(g_opt_decompress ? read_fd : -1);
    } else {
        dedup_mkdir(g_chunk_dir);
        compress_fd(read_fd);
    }

out:
    vol_buf_q_reinit(&in_q_free, 0);
    vol_buf_q_reinit(&comp_q_free, 0);
    free(g_zeroblock);
    free(g_chunk_dir);
    free(g_block_mapping);
    free(g_block_is_compressed);
    TAMP_LOG("exit: %s\n", !errors ? "SUCCESS" : "FAIL");
    return (errors);
}
