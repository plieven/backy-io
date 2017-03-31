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

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE       1024
#endif
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 7)
#endif
#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 8)
#endif

#pragma ident	"@(#)tamp.c	2.5	09/02/03 tim.cook@sun.com"

/* Is this GNU/Linux? */
#if defined(__linux__) || defined(__linux) || defined(linux)
#define	OS_LINUX	1
#endif

#ifndef	_REENTRANT
#define	_REENTRANT
#endif

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
#include <openssl/md5.h>

#include "jsmn/jsmn.h"

#ifdef OS_SOLARIS
#include <sys/isa_defs.h>
#include <netinet/in.h>		/* _BIG_ENDIAN */
#endif /* OS_SOLARIS */

#ifdef OS_LINUX
#include <stdint.h>
#include <malloc.h>		/* valloc() */
#include <endian.h>		/* __BYTE_ORDER = __{BIG,LITTLE}_ENDIAN */
#if (__BYTE_ORDER == __BIG_ENDIAN)
#define	_BIG_ENDIAN
#endif
#ifndef O_LARGEFILE
#define	O_LARGEFILE	0
#endif
#endif /* OS_LINUX */

#define	CBLK_SIZE		1024*1024	/* Default block size - 1024KB */
#define	MAX_CBLK_SIZE		4*1024*1024	/* 4MiB */
#define	MAX_OUTPUT_BUFFERS	64

#include "smhasher/src/MurmurHash3.h"
#define DEDUP_MAC_NAME "mmh3"
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

//~ #undef QUICKLZ
#define	LZO		1 

#ifdef LZO
#include <lzo/lzoconf.h>
#include <lzo/lzo1x.h>
#define	MAGIC_STRING		"t1o1"		/* LZO1X 2.20 */
#define	MAGIC_STRING_LENGTH	4
#define	COMPRESS_OVERHEAD	MAX_CBLK_SIZE / 64 + 16 + 3
#endif

MD5_CTX md5_c;
u_int8_t md5_digest[MD5_DIGEST_LENGTH];

uint32_t crc32c = 0xffffffff;
uint32_t crc32c_received = 0xffffffff;

#define	plural(n)	((n) == 1 ? "" : "s")

#ifndef	NDEBUG
#define	Tdebug(fmt, ...)	(void) fprintf(stderr, fmt, __VA_ARGS__)
#define	Tdebug1(fmt, ...)
#define	Tdebug2(fmt, ...)
#else
#define	Tdebug(...)
#define	Tdebug1(...)
#define	Tdebug2(...)
#endif

#define	dump_q(bufq)

/*
 * Strings used with die_if(), etc.
 */
static char g_estr_mutex_init[] =	"mutex_init";
#define	ESTR_MUTEX_INIT			g_estr_mutex_init
static char g_estr_cond_init[] =	"cond_init";
#define	ESTR_COND_INIT			g_estr_cond_init
static char g_estr_cond_signal[] =	"cond_signal";
#define	ESTR_COND_SIGNAL		g_estr_cond_signal
static char g_estr_cond_wait[] =	"cond_wait";
#define	ESTR_COND_WAIT			g_estr_cond_wait
static char g_estr_cond_broadcast[] =	"cond_broadcast";
#define	ESTR_COND_BROADCAST		g_estr_cond_broadcast
static char g_estr_mutex_lock[] =	"mutex_lock";
#define	ESTR_MUTEX_LOCK			g_estr_mutex_lock
static char g_estr_mutex_unlock[] =	"mutex_unlock";
#define	ESTR_MUTEX_UNLOCK		g_estr_mutex_unlock
static char g_estr_thread_create[] =	"thread_create";
#define	ESTR_THREAD_CREATE		g_estr_thread_create
static char g_estr_thread_attr_init[] =	"thread_attr_init";
#define	ESTR_THREAD_ATTR_INIT		g_estr_thread_attr_init
static char g_estr_thread_detached[] =	"thread_detached";
#define	ESTR_THREAD_DETACHED		g_estr_thread_detached
static char g_estr_thread_join[] =	"thread_join";
#define	ESTR_THREAD_JOIN		g_estr_thread_join
static char g_estr_malloc[] =		"malloc";
#define	ESTR_MALLOC			g_estr_malloc
static char g_estr_memalign[] =		"memalign";
#define	ESTR_MEMALIGN			g_estr_memalign
static char g_estr_write[] =		"write";
#define	ESTR_WRITE			g_estr_write
static char g_estr_read[] =		"read";
#define	ESTR_READ			g_estr_read
static char g_estr_fdopen[] =		"fdopen";
#define	ESTR_FDOPEN			g_estr_fdopen
static char g_estr_fread[] =		"fread";
#define	ESTR_FREAD			g_estr_fread


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
	struct vol_buf *next;		/* Next in the queue */
	u_int64_t bytes;		/* How big is the buffer */
	u_int64_t seq;		/* Sequence number */
	u_int8_t dedup_exists;
	u_int8_t _align[7];
	ulong_4char length;		/* How much is used */
	unsigned char buf[CBLK_SIZE];	/* the storage - may be more */
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

#define	WAIT	1
#define	NOWAIT	0

/* ======================================================================== */

static vol_buf_q in_q_free;	/* Used for reading in data */
static vol_buf_q in_q_dirty;	/* Containing data to be processed */
static vol_buf_q comp_q_free;	/* Used for output of compress/decompress */
static vol_buf_q comp_q_dirty;	/* Containing data to be output */

#ifndef NDEBUG
static vol_int in_q_alloc;	/* Buffers allocated for input */
static vol_int comp_q_alloc;	/* Buffers allocated for (de)compression */
#endif

static char *g_arg0;		/* Program name */
static char *g_out_path;	/* Output file */
static char *g_dedup_dir = "chunks";   /* directory with dedup tables */

static int g_write_fd;		/* File descriptor to output to */

static volatile uint64_t g_in_bytes = 0;		/* Bytes read */
static volatile uint64_t g_out_bytes = 0;	/* Bytes written */

static int g_opt_verbose = 0;		/* Verbose flag is set */
static int g_opt_decompress = 0;	/* Decompress is set */
static int g_single_file = 1;		/* Just do a single file */
static int g_opt_verify = -1;		/* Verify -1 disable, 0 simple, 1 deep */

static vol_int g_compress_threads;
static vol_int g_comp_idle;		/* Zero IFF all (de)compress threads */
					/* are busy processing */
static vol_int g_output_buffers;	/* Buffers to be output */
static vol_int g_comp_buffers;		/* Buffers to be (de)compressed */

static unsigned long g_max_threads;	/* Maximum (de)compress threads */
static unsigned long g_min_threads = 1;	/* Minimum (de)compress threads */

static char *g_stats_path = "(stdin)";
static void *g_zeroblock = NULL;

/* defaults */
static unsigned int g_block_size = 4096 * 1024;
static unsigned int g_version = 1;
static uint64_t g_filesize = 0;     /* size of the uncompressed data */
static uint64_t g_block_count = 0;
static char* g_block_mapping = NULL;
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

#define	DIAG_NOT_ERRNO		(-1)

/*
 * diag -	Print a diagnostic; preceded by g_arg0.
 *
 *	error	errno value (not used if < 0)
 *	format	printf-style format string
 *	...	arguments to be inserted into diagnostic
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

#define	die_if(cond, str)	{ \
	if (cond) { \
		diag(errno, str); exit(1); } }
#define	vdie_if(cond, str, ...)	{ \
	if (cond) { \
		diag(errno, str, __VA_ARGS__); exit(1); } }
#define	vdie_if_n(cond, str, ...) { \
	if (cond) { \
		diag(DIAG_NOT_ERRNO, str, __VA_ARGS__); exit(1); } }

/* Thread calls return 0 if OK, or an error */
#define	thr_die_iferr(stat, str) { \
	int ret = (stat); \
	if (ret != 0) { \
		diag(ret, str); exit(1); } }
#define	vthr_die_iferr(stat, str, ...) { \
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

void dedup_mkdir(u_int8_t * dir) {
      int ret;
      ret=mkdir(dir,0755);
      vdie_if((ret && (errno != EEXIST)),
       "mkdir: %s", dir);
}
//~ 
void dedup_hash_mkdir(u_int8_t * hash)
{
	  u_int8_t dir[DEDUP_HASH_FILENAME_MAX];
	  snprintf(dir,DEDUP_HASH_FILENAME_MAX,"%s/%02x",g_dedup_dir,hash[0]);
	  dedup_mkdir(dir);
	  snprintf(dir,DEDUP_HASH_FILENAME_MAX,"%s/%02x/%02x",g_dedup_dir,hash[0],hash[1]);
	  dedup_mkdir(dir);
}

static int dedup_hash_sprint(u_int8_t *hash, uint8_t *s) {
	int i;
	for (i=0; i < DEDUP_MAC_SIZE / 8; i++) {
		sprintf(s + i * 2, "%02x", hash[i]);
	}
}

void dedup_hash_filename(u_int8_t * filename, u_int8_t * hash)
{
	int i;
	snprintf(filename,DEDUP_HASH_FILENAME_MAX, "%s/%02x/%02x/", g_dedup_dir, hash[0], hash[1]);
	for (i=0; i < DEDUP_MAC_SIZE / 8;i++) {
		sprintf(filename + i * 2 + strlen(g_dedup_dir) + 2 * 3 + 1, "%02x", hash[i]);
	}
	if (g_version == 1) {
		sprintf(filename + i * 2 + strlen(g_dedup_dir) + 2 * 3 + 1, ".chunk.lzo");
	}
}

#include <emmintrin.h>
#define VECTYPE        __m128i
#define ALL_EQ(v1, v2) (_mm_movemask_epi8(_mm_cmpeq_epi8(v1, v2)) == 0xFFFF)

static int is_zero_block(unsigned char *bufp)
{
    VECTYPE *p = (VECTYPE *)bufp;
    VECTYPE zero = _mm_setzero_si128();
    int i;

    for (i = 0; i < g_block_size / sizeof(VECTYPE); i++) {
        if (!ALL_EQ(zero, p[i])) {
            return 0;
        }
    }

    return 1;
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
	vb = (vol_buf *)memalign(4, sizeof (vol_buf) - CBLK_SIZE + bytes);
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
 * vol_buf_q_reinit -	Re-initialize a vol_buf_q
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
	if (bufq->block_size < block_size) {
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
	bufp->next = (vol_buf *)NULL;	/* Safety */
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
	assert(bufq->last_block != 0);
	die_if(pthread_cond_broadcast(&(bufq->cv)) != 0,
		ESTR_COND_BROADCAST);
	die_if(pthread_mutex_unlock(&(bufq->mtx)) != 0,
		ESTR_MUTEX_UNLOCK);
}

void init_zero_block() {
	uint8_t h[DEDUP_MAC_SIZE / 4 + 1];
	g_zeroblock = malloc(g_block_size);
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

//~ /* ======================================================================== */
//~ 
//~ static void *
//~ write_compressed(void *arg)
//~ {
	//~ unsigned long seq;
	//~ unsigned long length;
	//~ unsigned long write_bytes;
	//~ unsigned char block_size[2];
	//~ vol_buf *bufp;
	//~ ssize_t bytes;
//~ #ifdef _BIG_ENDIAN
	//~ char x;
//~ #endif
	//~ int ret;
    //~ int dedup_new=0;
    //~ int dedup_existing=0;
    //~ 
	//~ g_out_bytes = 0;
//~ 
	//~ if (g_write_fd < 0)
		//~ vdie_if(((g_write_fd = open(g_out_path,
			//~ O_WRONLY | O_CREAT | O_LARGEFILE, 0666)) < 0),
			//~ "open: %s", g_out_path);
//~ 
	//~ /* Write magic number */
	//~ bytes = write(g_write_fd, MAGIC_STRING, MAGIC_STRING_LENGTH);
	//~ die_if(bytes != MAGIC_STRING_LENGTH, ESTR_WRITE);
	//~ g_out_bytes += bytes;
//~ 
	//~ /* Write block size */
	//~ block_size[1] = 0;
	//~ block_size[0] = (unsigned char)(g_block_size / (CBLK_SCALE * 1024));
	//~ bytes = write(g_write_fd, &block_size, sizeof (block_size));
	//~ die_if(bytes != sizeof (block_size), ESTR_WRITE);
	//~ g_out_bytes += bytes;
//~ 
	//~ seq = 1;
	//~ /*CONSTCOND*/
	//~ while (1) {
		//~ bufp = get_seq(&comp_q_dirty, seq);
		//~ if (! bufp) {
			//~ assert(seq > comp_q_dirty.last_block);
			//~ break;
		//~ }
		//~ (void) decrement(&g_output_buffers);
//~ 
		//~ length = bufp->length.val;
		//~ if (g_opt_verbose > 2)
			//~ /* Bytes here is the compressed length */
			//~ TAMP_LOG( "  block %ld - %ld bytes - written so far %ld\n",	seq, length,g_out_bytes);
//~ 
		//~ /* Write our bufp */
//~ #ifdef _BIG_ENDIAN
		//~ /* Native byte 0 is MSB */
		//~ bufp->length.bytes[0] = bufp->length.bytes[3];
		//~ x = bufp->length.bytes[1];
		//~ bufp->length.bytes[1] = bufp->length.bytes[2];
		//~ bufp->length.bytes[2] = x;
		//~ bufp->length.bytes[3] = (char)0;
//~ #endif
		//~ assert(length <= g_block_size);
//~ 
		//~ /*
		 //~ * Save the last byte in the highest-order byte of
		 //~ * the length field
		 //~ */
		//~ bufp->length.bytes[3] = bufp->buf[length - 1];
		//~ write_bytes = length - 1 + sizeof (bufp->length);
//~ 
        //~ if (bufp->length.val==g_block_size && bufp->is_zero_block) {
			//~ bufp->length.val=ZEROBLOCK_MAGIC;
			//~ bufp->length.bytes[3]=0x00;
			//~ bytes=write(g_write_fd,(const void *)&(bufp->length),sizeof (bufp->length));
			//~ die_if(bytes < 0, ESTR_WRITE);	
		//~ }
		//~ else
        //~ if (!g_opt_dedup || bufp->length.val==0) {
		 //~ if (bufp->length.val==0) {
			//~ int bytes;
			//~ ulong_4char length;
	        //~ length.val = CRC32C_MAGIC;
	        //~ length.bytes[3]=0x00;
			//~ bytes=write(g_write_fd,(const void *)&(length),sizeof (length));
			//~ die_if(bytes < 0, ESTR_WRITE);			
			//~ bytes=write(g_write_fd,&crc32c,sizeof(crc32c));
			//~ die_if(bytes < 0, ESTR_WRITE);			
			//~ bytes=5+sizeof(bufp->length)-1;
			//~ g_out_bytes += bytes;
		//~ }
		 //~ /* Write it */
		 //~ bytes = write(g_write_fd, (const void *)&(bufp->length),
		 	 //~ write_bytes);
		 //~ die_if(bytes < 0, ESTR_WRITE);
		//~ }
		//~ else
	    //~ {
		    //~ u_int8_t dedup_file[DEDUP_HASH_FILENAME_MAX];
			//~ dedup_hash_filename(dedup_file,bufp->dedup_hash);
		    //~ if (!bufp->dedup_exists) {
			   	//~ //write to dedup
			   	//~ dedup_hash_mkdir(bufp->dedup_hash);
//~ 
			   	//~ int g_write_fd_dedup;
			   	//~ g_write_fd_dedup = open(dedup_file,
			      //~ O_WRONLY | O_LARGEFILE | O_CREAT | O_EXCL, 0666);
			    //~ if (g_write_fd_dedup < 0) {
					//~ if (errno != EEXIST) {
						//~ vdie_if(1,"dedup chunk write: %s", dedup_file);
					//~ }
					//~ TAMP_LOG("dedup write collision: %s (length %lu)\n", dedup_file, bufp->length.val);
					//~ dedup_existing++;
				//~ } else {
					//~ bytes = write(g_write_fd_dedup, (const void *)&(bufp->length),
						//~ write_bytes);
					//~ close(g_write_fd_dedup);
					//~ if (bytes < 0)
						//~ unlink(dedup_file);
					//~ die_if(bytes < 0, ESTR_WRITE);
					//~ dedup_new++;
				//~ }
			//~ }
			//~ else
			//~ {
			    //~ dedup_existing++;
			    //~ //touch dedup_file is not necessary because file_exists updates atime
			//~ }
			//~ bufp->length.val=DEDUP_MAGIC;
			//~ bufp->length.bytes[3]=bufp->dedup_hash[SHA512_DIGEST_LENGTH-1];
			//~ bytes=write(g_write_fd,(const void *)&(bufp->length),sizeof (bufp->length));
			//~ die_if(bytes < 0, ESTR_WRITE);			
			//~ bytes=write(g_write_fd,(const void *)&(bufp->dedup_hash),SHA512_DIGEST_LENGTH-1);
			//~ die_if(bytes < 0, ESTR_WRITE);			
			//~ bytes=SHA512_DIGEST_LENGTH+sizeof(bufp->length)-1;
		//~ }	
//~ 
		//~ g_out_bytes += bytes;
//~ 
		//~ /* Buffer is now free */
		//~ put_last(&comp_q_free, bufp);
//~ 
		//~ seq++;
	//~ }
//~ 
    //~ //TODO: add zeroblocks stat
    //~ //TODO: add dedup stats
//~ 
	//~ ret = ftruncate(g_write_fd, g_out_bytes);
//~ 
    //~ TAMP_LOG("dedup: %d new %d existing\n",dedup_new,dedup_existing);
//~ 
	//~ return (NULL);
//~ }
//~ 
//~ /*
 //~ * compress() -	Runs as thread(s) started via pthread_create()
 //~ */
//~ static void *
//~ compress(void *arg)
//~ {
	//~ vol_buf *bufp;
	//~ vol_buf *comp_bufp;
	//~ unsigned long sequence;
	//~ char *work_buf;
//~ #ifndef NDEBUG
	//~ int blocks_compressed = 0;
//~ #endif
//~ 
	//~ (void) increment(&g_compress_threads);
//~ #ifdef LZO
	//~ /* Need to initialise work_buf */
	//~ work_buf = valloc(LZO1X_1_MEM_COMPRESS);
//~ #endif
//~ #ifdef QUICKLZ
	//~ work_buf = valloc(QLZ_SCRATCH_COMPRESS);
//~ #endif
	//~ die_if(! work_buf, ESTR_MEMALIGN);
//~ 
    //~ SHA512_CTX * dedup_c;
    //~ u_int8_t * dedup_filename;
    //~ 
    //~ if (g_opt_dedup) {
     //~ dedup_c = valloc(sizeof(SHA512_CTX));
     //~ die_if(! dedup_c, ESTR_MEMALIGN);
     //~ dedup_filename = valloc(DEDUP_HASH_FILENAME_MAX);
     //~ die_if(! dedup_filename, ESTR_MEMALIGN);
    //~ }
//~ 
	//~ /*CONSTCOND*/
	//~ while (1) {
		//~ /* Get an output buffer */
		//~ comp_bufp = get_first(&comp_q_free, NOWAIT);
		//~ if (! comp_bufp) {
			//~ /* THROTTLE: Wait if output queue is "full" */
			//~ if (g_output_buffers.value >= MAX_OUTPUT_BUFFERS)
				//~ /* Allow them to drain */
				//~ comp_bufp = get_first(&comp_q_free, WAIT);
			//~ else {
				//~ /* Get a new buffer */
				//~ comp_bufp = vol_buf_new(g_block_size +
					//~ COMPRESS_OVERHEAD +
					//~ sizeof (bufp->length));
//~ #ifndef NDEBUG
				//~ (void) increment(&comp_q_alloc);
//~ #endif
			//~ }
		//~ }
		//~ assert(comp_bufp);
//~ 
		//~ /* Get a buffer to compress */
		//~ bufp = get_first(&in_q_dirty, WAIT);
		//~ if (! bufp) {
			//~ /* No more work to do */
			//~ /* No longer need output buffer, so put it back */
			//~ put_last(&comp_q_free, comp_bufp);
			//~ break;
		//~ }
		//~ (void) decrement(&g_comp_buffers);
//~ 
		//~ /* Compress */
		//~ (void) decrement(&g_comp_idle);
		//~ 
		//~ comp_bufp->is_zero_block=bufp->is_zero_block=0;
		//~ comp_bufp->dedup_exists=bufp->dedup_exists=0;
//~ 
        //~ if (bufp->length.val==g_block_size && is_zero_block(bufp->buf)) {
			//~ comp_bufp->is_zero_block=bufp->is_zero_block=1;
			//~ if (g_opt_verbose >2) {
				//~ TAMP_LOG("block (%lu) length:%lu is all ZERO\n",bufp->seq,bufp->length.val);
			//~ }
		//~ }
		//~ 
		//~ 
		//~ if (!bufp->is_zero_block && bufp->length.val > 0 && g_opt_dedup) {
		    //~ SHA512_Init(dedup_c);	
			//~ SHA512_Update(dedup_c, &(bufp->buf), bufp->length.val);
            //~ SHA512_Final(bufp->dedup_hash, dedup_c);
            //~ dedup_hash_filename(dedup_filename,bufp->dedup_hash);
            //~ if (g_opt_verbose >2) {
			 //~ TAMP_LOG("DEDUP block (%lu) length:%lu sha512: ",bufp->seq,bufp->length.val);
			 //~ int i;
	         //~ for (i=0;i<SHA512_DIGEST_LENGTH;i++)
	          //~ TAMP_LOG("%02x",bufp->dedup_hash[i]);
	         //~ TAMP_LOG("\n");
	         //~ TAMP_LOG("DEDUP block (%lu) filename: %s\n",bufp->seq,dedup_filename);
            //~ }
            //~ comp_bufp->dedup_exists=bufp->dedup_exists=file_exists(dedup_filename);
            //~ if (bufp->dedup_exists) {
				//~ int i;
				//~ char tmp[SHA512_DIGEST_LENGTH*2+1];
				//~ for (i=0;i<SHA512_DIGEST_LENGTH;i++)
					//~ snprintf(&tmp[i*2],3,"%02x",bufp->dedup_hash[i]);
				//~ TAMP_LOG("DEDUP: %s\n",tmp);
			//~ }
		//~ }
		//~ 
		//~ if (!bufp->dedup_exists && !bufp->is_zero_block)
		 //~ {
		//~ 
//~ #ifdef LZO
		//~ (void) lzo1x_1_compress(
			//~ (unsigned char *) &(bufp->buf),
			//~ bufp->length.val,
			//~ (unsigned char *) &(comp_bufp->buf),
			//~ (unsigned long *) &(comp_bufp->length),
			//~ work_buf);
//~ #endif
//~ #ifdef QUICKLZ
		//~ comp_bufp->length.val = qlz_compress(bufp->buf,
			//~ (char *)comp_bufp->buf,
			//~ bufp->length.val, work_buf);
//~ #endif
	   //~ }
//~ 
		//~ (void) increment(&g_comp_idle);
//~ 
		//~ /* Set the sequence number */
		//~ sequence = bufp->seq;
		//~ comp_bufp->seq = sequence;
//~ 
		//~ /* Did we get negative compression? */
		//~ if (bufp->is_zero_block || bufp->dedup_exists || (
		    //~ comp_bufp->length.val >= g_block_size &&
		    //~ bufp->length.val == g_block_size)) {
			//~ /* Yes - write out original block */
			//~ put_last(&in_q_free, comp_bufp);
			//~ put_last(&comp_q_dirty, bufp);
		//~ } else {
			//~ /*
			 //~ * No - post the input buffer back to the input
			 //~ * thread's free list, and the decompressed buffer
			 //~ * on to the queue for the write thread.
			 //~ */
			//~ memcpy(&comp_bufp->dedup_hash,&bufp->dedup_hash,SHA512_DIGEST_LENGTH);
			//~ put_last(&in_q_free, bufp);
			//~ put_last(&comp_q_dirty, comp_bufp);
		//~ }
//~ #ifndef NDEBUG
		//~ blocks_compressed++;
//~ #endif
		//~ (void) increment(&g_output_buffers);
	//~ }
	//~ (void) decrement(&g_comp_idle);
//~ 
	//~ set_last_block(&comp_q_dirty, in_q_dirty.last_block);
	//~ if (in_q_dirty.last_block == sequence)
		//~ wakeup(&comp_q_dirty);
//~ #if defined(LZO) || defined(QUICKLZ)
	//~ free(work_buf);
//~ #endif
    //~ if (g_opt_dedup) {
     //~ free(dedup_c);
     //~ free(dedup_filename);
    //~ }
//~ 
	//~ Tdebug2("+ compress() - return; tid = %d, blocks = %d\n",
		//~ pthread_self, blocks_compressed);
	//~ return (NULL);
//~ }
//~ 
//~ /*
 //~ * compress_fd -	Compress a stream of bytes
 //~ *
 //~ *	fd	File descriptor, readable
 //~ */
//~ 
//~ static void
//~ compress_fd(int fd)
//~ {
	//~ unsigned char *readp;
	//~ pthread_t compress_thr;
	//~ pthread_t write_thr;
	//~ pthread_attr_t compress_thr_attr;
	//~ void *wr_status;
	//~ ssize_t bytes, b;
	//~ unsigned long sequence = 1;
	//~ unsigned long i;
	//~ vol_buf *bufp;
//~ #ifdef LZO
	//~ int ret;
//~ #endif
//~ 
	//~ assert(vol_int_get(&g_compress_threads) == 0);
	//~ assert(vol_int_get(&g_comp_idle) == 0);
	//~ assert(vol_int_get(&g_output_buffers) == 0);
	//~ assert(vol_int_get(&g_comp_buffers) == 0);
//~ 
	//~ /* Initialize LZ01X-1 */
	//~ if ((ret = lzo_init()) != LZO_E_OK) {
		//~ diag(DIAG_NOT_ERRNO, "lzo_init failed (%d)\n", ret);
		//~ exit(1);
	//~ }
//~ 
	//~ /* Initialize compress thread attributes */
	//~ thr_die_iferr(pthread_attr_init(&compress_thr_attr),
		//~ ESTR_THREAD_ATTR_INIT);
	//~ thr_die_iferr(pthread_attr_setdetachstate(&compress_thr_attr,
		//~ PTHREAD_CREATE_DETACHED), ESTR_THREAD_DETACHED);
//~ 
	//~ /* Start minimum compress threads */
	//~ for (i = 0; i < g_min_threads; i++) {
		//~ Tdebug2("+ pthread_create(compress) [PRE LOOP]\n", NULL);
		//~ (void) increment(&g_comp_idle);
		//~ thr_die_iferr(pthread_create(&compress_thr, &compress_thr_attr,
			//~ compress, NULL), ESTR_THREAD_CREATE);
	//~ }
//~ 
	//~ /* Start output thread */
	//~ thr_die_iferr(pthread_create(&write_thr, NULL, write_compressed, NULL),
		//~ ESTR_THREAD_CREATE);
//~ 
	//~ /*CONSTCOND*/
	//~ while (1) {
		//~ /* Get a read buffer */
		//~ if (g_comp_buffers.value >= MAX_OUTPUT_BUFFERS) {
			//~ /* Allow buffers to drain */
			//~ bufp = get_first(&in_q_free, WAIT);
		//~ } else {
			//~ /* Try, then get a new buffer */
			//~ bufp = get_first(&in_q_free, NOWAIT);
			//~ if (! bufp) {
				//~ bufp = vol_buf_new(g_block_size +
					//~ COMPRESS_OVERHEAD +
					//~ sizeof (bufp->length));
//~ #ifndef NDEBUG
				//~ (void) increment(&in_q_alloc);
//~ #endif
			//~ }
		//~ }
		//~ assert(bufp);
		//~ readp = (unsigned char *)&(bufp->buf);
//~ 
		//~ /*
		 //~ * Do the read(s) - we need to keep issuing read()'s until
		 //~ * we have filled our g_block_size buffer, or got a zero read,
		 //~ * as we will get short reads from fifofs.
		 //~ */
		//~ bytes = 0;
		//~ while (bytes < g_block_size) {
			//~ int max_read = g_block_size - bytes;
			//~ b = read(fd, readp, max_read);
			//~ if (b == 0)
				//~ /* EOF */
				//~ break;
			//~ die_if(b < 0, ESTR_READ);
			//~ bytes += b;
			//~ readp += b;
		//~ }
		//~ g_in_bytes += (uint64_t)bytes;
		//~ if (g_opt_verbose) TAMP_LOG("%lu bytes read.\n",g_in_bytes);
		//~ crc32c=crc32c_hardware(crc32c,(const u_int8_t *) bufp->buf,bytes);
		//~ bufp->length.val = bytes;
		//~ bufp->seq = sequence;
//~ 
		//~ /* Post the buffer to be compressed */
		//~ put_last(&in_q_dirty, bufp);
		//~ (void) increment(&g_comp_buffers);
//~ 
		//~ /* THROTTLE: Do we want to start another compress thread? */
		//~ if (g_comp_idle.value < 1 &&
		    //~ g_output_buffers.value <= MAX_OUTPUT_BUFFERS &&
		    //~ g_compress_threads.value < g_max_threads) {
			//~ Tdebug2("+ pthread_create(compress) %d\n",
				//~ g_comp_idle.value);
			//~ (void) increment(&g_comp_idle);
			//~ thr_die_iferr(pthread_create(&compress_thr, NULL,
				//~ compress, NULL), ESTR_THREAD_CREATE);
		//~ }
//~ 
		//~ /* Is it the last block? */
		//~ if (bytes < g_block_size) {
			//~ set_last_block(&in_q_dirty, sequence);
			//~ break;
		//~ }
//~ 
		//~ sequence++;
	//~ }
//~ 
	//~ /* Wake up any remaining compress threads */
	//~ wakeup(&in_q_dirty);
//~ 
	//~ /* Wait for the output thread to complete */
	//~ thr_die_iferr(pthread_join(write_thr, &wr_status), ESTR_THREAD_JOIN);
//~ 
	//~ if (g_opt_verbose) {
		//~ /* Report statistics */
		//~ if (g_out_bytes < g_in_bytes)
			//~ TAMP_LOG(
				//~ "%s: read %llu, wrote %llu (-%3.1f%%),"
				//~ " %d thread%s\n",
				//~ g_stats_path, (unsigned long long)g_in_bytes,
				//~ (unsigned long long)g_out_bytes,
				//~ (double)(g_in_bytes - g_out_bytes)
				//~ / (double)g_in_bytes * 100.0,
				//~ g_compress_threads.value,
				//~ plural(g_compress_threads.value));
		//~ else
			//~ TAMP_LOG(
				//~ "%s: read %llu, wrote %llu (+%.3f%%),"
				//~ " %d thread%s\n",
				//~ g_stats_path, (unsigned long long)g_in_bytes,
				//~ (unsigned long long)g_out_bytes,
				//~ (double)(g_out_bytes - g_in_bytes)
				//~ / (double)g_in_bytes * 100.0,
				//~ g_compress_threads.value,
				//~ plural(g_compress_threads.value));
	//~ }
//~ }
//~ 
//~ 
//~ 
//~ 
//~ 
static void *
write_decompressed(void *arg)
{
	unsigned long sequence;
	vol_buf *bufp;
	ssize_t bytes;

	g_out_bytes = 0;

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

	sequence = 0;
	/*CONSTCOND*/
	while (1) {
		bufp = get_seq(&comp_q_dirty, sequence);
		if (! bufp) {
			/* We missed g_last_block being set */
			assert(sequence > comp_q_dirty.last_block);
			break;
		}
		(void) decrement(&g_output_buffers);
		
		bytes = MIN(bufp->length.val, g_filesize - g_out_bytes);

		 bytes = write(g_write_fd, bufp->buf, bytes);
		 die_if(bytes < 0, ESTR_WRITE);
		 g_out_bytes += bytes;
		 crc32c=crc32c_hardware(crc32c,(const u_int8_t *) bufp->buf, bytes);

		if (g_opt_verbose) {
			TAMP_LOG("progress: %lu bytes written.\n", g_out_bytes);
		}

		/* We can free that buffer */
		put_last(&comp_q_free, bufp);

		sequence++;
	}

	vdie_if_n(g_out_bytes != g_filesize, "out_bytes does not match size (%lu != %lu)\n", g_out_bytes, g_filesize);

	//XXX: read crc32c from json
	if (crc32c_received != 0xffffffff) {
		TAMP_LOG("received crc32c = %08x, computed crc32c %08x\n",crc32c_received, crc32c);
		vdie_if_n(crc32c != crc32c_received,"crc32c checksum failure.\n",0);
	}


	return (NULL);
}

static void *
decompress(void *arg)
{
	vol_buf *bufp, *comp_bufp;
#ifdef LZO
	int ret;
#endif
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
					COMPRESS_OVERHEAD +
					sizeof (comp_bufp->length));
#ifndef NDEBUG
				(void) increment(&comp_q_alloc);
#endif
			}
		}
		assert(comp_bufp);

		/* Get a buffer to decompress */
		bufp = get_first(&in_q_dirty, WAIT);
		if (! bufp) {
			/* No more work to do */
			/* No longer need output buffer, so put it back */
			put_last(&comp_q_free, comp_bufp);
			break;
		}
		(void) decrement(&g_comp_buffers);
		
		//XXX: avoid wasting a buffer for this?!
		if (dedup_is_zero_chunk(g_block_mapping + bufp->seq * DEDUP_MAC_SIZE / 8)) {
			put_last(&in_q_free, comp_bufp);
			put_last(&comp_q_dirty, bufp);
			memset(bufp->buf, 0x00, g_block_size);
			bufp->length.val = g_block_size;
			(void) increment(&g_output_buffers);
			continue;
		}
		
          int read_fd_dedup;
		  u_int8_t dedup_file[DEDUP_HASH_FILENAME_MAX];
		  dedup_hash_filename(dedup_file, g_block_mapping + bufp->seq * DEDUP_MAC_SIZE / 8);
          vdie_if((read_fd_dedup = open(dedup_file,
			      O_RDONLY)) < 0,
			       "open: %s", dedup_file);
		die_if((bufp->length.val = read(read_fd_dedup,(void *)&(bufp->buf), bufp->bytes)) < 0,ESTR_FREAD);
		close(read_fd_dedup);
		g_in_bytes += bufp->length.val;
		if (g_opt_verbose > 1) {
		 	      TAMP_LOG("dedup: successfully read %lu bytes from %s %lu\n",bufp->length.val,dedup_file,bufp->bytes);
		}

		/* Set the sequence number */
		comp_bufp->seq = bufp->seq;

		if (bufp->length.val == g_block_size && g_version > 1) {
			put_last(&in_q_free, comp_bufp);
			put_last(&comp_q_dirty, bufp);
			//XXX: verify if the hash is ok ?!
		} else {
			(void) decrement(&g_comp_idle);
			vdie_if_n(bufp->buf[0] != 0xf0 || bufp->length.val < 5 + 3, "lzo header error\n", 0);
			comp_bufp->length.val = (bufp->buf[1] << 24) | (bufp->buf[2] << 16) | (bufp->buf[3] << 8) | bufp->buf[4];
			vdie_if_n(comp_bufp->length.val < 0 || bufp->length.val - 5 > comp_bufp->length.val + comp_bufp->length.val / 64 + 16 + 3, "lzo header error\n", 0);
			vdie_if_n(comp_bufp->length.val != g_block_size, "lzo data does not match block size\n", 0);
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
				"return 	= %d\n", g_arg0, ret);
				exit(1);
			}
			
			//XXX: verify if the hash is ok ?!

			(void) increment(&g_comp_idle);
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
		(void) increment(&g_output_buffers);
	}
	(void) decrement(&g_comp_idle);
	assert(in_q_dirty.last_block != 0);
	set_last_block(&comp_q_dirty, in_q_dirty.last_block);
	wakeup(&comp_q_dirty);

	Tdebug2("+ decompress() - return; tid = %d, blocks = %d\n",
		pthread_self, blocks_compressed);
	return (NULL);
}

#define	VBUF_SIZE	65536
#define	BUF_SIZE	65536

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
		} else if (jsoneq(buf, tok + i, "blocksize_kb") == 0) {
			g_block_size = strtol(buf + (tok + i + 1)->start, NULL, 0) * 1024;
			i++;
		} else if (jsoneq(buf, tok + i, "mapping") == 0) {
			vdie_if_n((tok + i + 1)->type != JSMN_OBJECT, "json parser error: mapping has unexpected type (%d)\n", (tok + i + 1)->type);
			g_block_count = (tok + i + 1)->size;
			i+=2;
			die_if(g_block_mapping, ESTR_MALLOC);
			g_block_mapping = malloc((DEDUP_MAC_SIZE / 8) * g_block_count);
			die_if(!g_block_mapping, ESTR_MALLOC);
			for (j = i; j < i + g_block_count * 2; j += 2) {
				unsigned long seq = strtol(buf + (tok + j)->start, NULL, 0);
				vdie_if_n(seq != (j - i) / 2, "json parser error: invalid sequence in mapping: expected %lu found %lu\n", (j - i) / 2, seq);
				vdie_if_n((tok + j +1)->end - (tok + j +1)->start != DEDUP_MAC_SIZE / 4, "json parser error: invalid mac size in mapping: expected %d found %d\n", DEDUP_MAC_SIZE / 4, (tok + j +1)->end - (tok + j +1)->start);
				for (k = 0; k < DEDUP_MAC_SIZE / 8; k++) {
					g_block_mapping[seq * DEDUP_MAC_SIZE / 8 + k] = (hex2dec(buf[(tok + j + 1)->start + k * 2]) << 4) +
					                                                hex2dec(buf[(tok + j + 1)->start + k * 2 + 1]);
				}
			}
		}
	}

	vdie_if_n(g_version < 1 || g_version > 2, "unsupported version %d\n", g_version);
	vdie_if_n(g_block_size != 1024*1024 && g_block_size != 4096*1024, "unsupported block size %lu\n", g_block_size);

	TAMP_LOG("version: %d\n", g_version);
	TAMP_LOG("blocksize: %u\n", g_block_size);
	TAMP_LOG("size: %lu\n", g_filesize);

	vdie_if_n(g_block_count != (g_filesize + g_block_size - 1) / (g_block_size), "invalid number of chunks: expected %lu found %lu\n", (g_filesize + g_block_size - 1) / (g_block_size), g_block_count);

	TAMP_LOG("blockcount: %lu\n", g_block_count);

	free(tok);
	free(buf);
	fclose(input);
}

void verify_chunks(int deep) {
	u_int8_t chunk_file[DEDUP_HASH_FILENAME_MAX];
	vdie_if_n(deep, "deep verify is not implemented yet", 0);
	int i;
	for (i = 0; i < g_block_count; i++) {
		dedup_hash_filename(chunk_file, g_block_mapping + i * DEDUP_MAC_SIZE / 8);
		vdie_if_n(!file_exists(chunk_file), "verify: chunk %s does not exist\n", chunk_file);
	}
	if (!deep) {
		TAMP_LOG("verify_simple: all chunks available\n");
	}
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

#ifdef LZO
	/* Initialize LZ01X-1 */
	if ((ret = lzo_init()) != LZO_E_OK) {
		diag(-1, "lzo_init failed (%d)\n", ret);
		exit(1);
	}
#endif

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
		/* Get a read buffer */
		if (g_comp_buffers.value >= MAX_OUTPUT_BUFFERS) {
			/* Allow buffers to drain */
			bufp = get_first(&in_q_free, WAIT);
		} else {
			/* Try, then get a new buffer */
			bufp = get_first(&in_q_free, NOWAIT);
			if (! bufp) {
				bufp = vol_buf_new(g_block_size +
					COMPRESS_OVERHEAD +
					sizeof (bufp->length));
#ifndef NDEBUG
				(void) increment(&in_q_alloc);
#endif
			}
		}
		assert(bufp);

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
		(void) increment(&g_comp_buffers);
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

	read_fd = 0;		/* stdin */
	g_write_fd = 1;		/* stdout */

	/* Default maximum threads */
	g_max_threads = sysconf(_SC_NPROCESSORS_ONLN);

	while ((c = getopt(argc, argv, "dDvnci:o:b:m:t:p:X:r:")) != -1) {
		switch (c) {
		case 'd':
			g_opt_decompress = 1;
			if (g_opt_verify == -1) g_opt_verify = 0;
			break;
		case 'v':
			g_opt_verbose++;
			break;
		case 'i':
			/* Input file specified */
			g_single_file++;
			g_stats_path = optarg;
			vdie_if((read_fd = open(optarg, O_RDONLY | O_LARGEFILE,
				0)) < 0, "open: %s", optarg);
			break;
		case 'o':
			/* Output file specified */
			g_single_file++;
			g_out_path = optarg;
			g_write_fd = -1;
			break;
		case 'b':
			/* Block size */
			g_block_size = atoi(optarg) * 1024;
			vdie_if_n(g_block_size > MAX_CBLK_SIZE,
				"block size (%s KB) can not exceed %d\n",
				optarg, MAX_CBLK_SIZE / 1024);
			break;
		case 'm':
			g_min_threads = atol(optarg);
			break;
		case 't':
		case 'p':
			g_max_threads = atol(optarg);
			break;
		case 'X':
		    g_opt_dedup=1;
		    g_dedup_dir = optarg;
		    //TAMP_LOG("enabling dedup with digest %s\n", DEDUP_MAC_NAME);
		    break;
		case '?':
			opt_error++;
		}
	}

	//if (!g_opt_dedup) opt_error++;

	if (g_single_file && (argc != optind))
		/*
		 * We can run on a single file, potentially with
		 * -i/-o, or with a list given as args
		 */
		opt_error++;
	if (opt_error) {
		TAMP_LOG(
			"usage: %1$s [-dDvnc] [-p maxthr] [-m minthr]"
			" [-b blkKB] [-r readKB] [-i file] [-o file]\n"
			"or:    %1$s [-dDv] [-p p] [-m m] [-b b] [file ...]\n",
			g_arg0);
		exit(2);
	}

	if (optind == argc)
		g_single_file = 1;

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

    TAMP_LOG("pid: %d\n",getpid());

	if (g_opt_verbose > 1)
		if (g_opt_decompress)
			TAMP_LOG( "%s: max threads %lu\n",
				g_arg0, g_max_threads);
		else
			TAMP_LOG(
				"%s: block size %uKB, max threads %lu\n",
				g_arg0, g_block_size / 1024, g_max_threads);

	if (g_opt_decompress) {
		parse_json(read_fd);
		init_zero_block();
		if (g_opt_verify) verify_chunks(g_opt_verify);
		decompress_fd(read_fd);
	} else {
		vdie_if_n(1, "work in progress\n", 0);
		compress_fd(read_fd);
	}

	if (g_opt_verbose && !g_opt_decompress) TAMP_LOG("%lu bytes read.\n",g_in_bytes);
	if (g_opt_verbose && g_opt_decompress) TAMP_LOG("%lu bytes written.\n",g_out_bytes);

	TAMP_LOG("crc32c: %08x\n",crc32c);

	free(g_zeroblock);

	return (errors);
}
