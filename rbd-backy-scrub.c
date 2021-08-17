#include "backy.h"

#define DEBUG_PREFIX "rbd-backy-scrub"

#include "rbd-backy.h"

char *errormap = NULL;
char *zeromap = NULL;
struct rbd_connection conn = {0};

#pragma GCC push_options
#pragma GCC target("avx512f")
#include <immintrin.h>
#define unlikely(x)     __builtin_expect((x),0)

static bool
buffer_zero_avx512(const void *buf, size_t len)
{
    /* Begin with an unaligned head of 64 bytes.  */
    __m512i t = _mm512_loadu_si512(buf);
    __m512i *p = (__m512i *)(((uintptr_t)buf + 5 * 64) & -64);
    __m512i *e = (__m512i *)(((uintptr_t)buf + len) & -64);

    /* Loop over 64-byte aligned blocks of 256.  */
    while (p <= e) {
        __builtin_prefetch(p);
        if (unlikely(_mm512_test_epi64_mask(t, t))) {
            return false;
        }
        t = p[-4] | p[-3] | p[-2] | p[-1];
        p += 4;
    }

    t |= _mm512_loadu_si512(buf + len - 4 * 64);
    t |= _mm512_loadu_si512(buf + len - 3 * 64);
    t |= _mm512_loadu_si512(buf + len - 2 * 64);
    t |= _mm512_loadu_si512(buf + len - 1 * 64);

    return !_mm512_test_epi64_mask(t, t);
}

int read_cb(uint64_t offs, size_t len, const char * buf, void *opaque) {
    char h[DEDUP_MAC_SIZE_BYTES];
    long i = offs >> conn.info.order;
    assert(len == conn.info.obj_size);
    assert(!(offs & (conn.info.obj_size - 1)));
    if (!buf || buffer_zero_avx512(buf, len)) {
        OBJ_SET_ALLOCATED(zeromap, i);
        if (!dedup_is_zero_chunk(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES)) {
            OBJ_SET_ALLOCATED(errormap, i);
        }
    } else {
        mmh3(buf, len, 0, &h[0]);
        if (memcmp(&h[0], g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, DEDUP_MAC_SIZE_BYTES)) {
            OBJ_SET_ALLOCATED(errormap, i);
        }
    }
    fprintf(stderr, "progress: %lu bytes read\n", offs + len);
    return 0;
}

int main(int argc, char** argv) {
	int ret = 1;
	long changed_api = 0, changed_csum = 0, zero_blocks = 0, unallocated_blocks = 0;
	long i;
    time_t since = 0;
    char *old_snap_name = NULL;
    struct timespec tstart={}, tend={};

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <rbd-path> <backy-json>\n", argv[0]);
		exit(1);
	}

    char *arg_path = argv[1];
    char *arg_old = argv[2];

	pthread_mutex_init(&log_mutex, NULL);

    if (backy_rbd_connect(arg_path, &conn)) {
        fprintf(stderr, "backy_rbd_connect: %s (%s)\n", arg_path, strerror(errno));
        if (errno == ENOENT) {
            ret = 4;
        }
        goto out;
    }

    if (rbd_parse_json(&conn, arg_old, &since, &old_snap_name)) {
        goto out;
    }
    if (!since) {
        fprintf(stderr, "SKIP: could not parse ts of old_snapshot\n");
        ret = 3;
        goto out;
    }

	if (conn.info.size != g_filesize) {
		fprintf(stderr, "SKIP: filesize changed from %lu to %lu\n", g_filesize, conn.info.size);
		ret = 3;
		goto out;
	}

	errormap = calloc(1, conn.bitmap_sz);
	assert(errormap);

	zeromap = calloc(1, conn.bitmap_sz);
	assert(zeromap);

    init_zero_block();

    clock_gettime(CLOCK_MONOTONIC, &tstart);
    ret = rbd_read_iterate2(conn.image, 0, conn.info.size, read_cb, NULL);
    clock_gettime(CLOCK_MONOTONIC, &tend);
    fprintf(stderr, "rbd_backy_scrub (read of complete image) took about %.5f seconds\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
    assert(ret >= 0);

    if (old_snap_name) {
        if (backy_rbd_changed_objs_from_snap(&conn, old_snap_name) < 0) {
            goto out;
        }
    } else {
        if (backy_rbd_changed_objs(&conn, since) < 0) {
            goto out;
        }
    }

    for (i = 0; i < conn.info.num_objs; i++) {
        if (OBJ_IS_ALLOCATED(conn.alloc_bitmap, i) && OBJ_IS_ALLOCATED(errormap, i)) {
            if (!OBJ_IS_ALLOCATED(conn.change_bitmap, i)) {
                char dedup_hash[DEDUP_MAC_SIZE_STR] = {};
                fprintf(stderr, "FATAL ERROR: object #%lu failed checksum test, but is not marked as changed\n", i);
                dedup_hash_sprint(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, &dedup_hash[0]);
                fprintf(stderr, "FATAL ERROR: object #%lu hash on backup: %s\n", i, dedup_hash);
                ret = 2;
                goto out;
            } else {
                changed_csum++;
            }
        }
        if (!OBJ_IS_ALLOCATED(conn.alloc_bitmap, i)) {
            unallocated_blocks++;
            if (!OBJ_IS_ALLOCATED(zeromap, i) && !OBJ_IS_ALLOCATED(conn.change_bitmap, i)) {
                fprintf(stderr, "FATAL ERROR: object #%lu is not allocated, but did not read as zero\n", i);
                ret = 2;
                goto out;
            }
        }
        if (OBJ_IS_ALLOCATED(zeromap, i)) {
            zero_blocks++;
        }
        if (OBJ_IS_ALLOCATED(conn.change_bitmap, i)) {
            changed_api++;
        }
    }

	fprintf(stderr, "SUCCESS: all objects passed scrubbing test. changed_api: %lu changed_csum: %lu unallocated: %lu read_zero: %lu total: %lu\n", changed_api, changed_csum, unallocated_blocks, zero_blocks, conn.info.num_objs);

	ret = 0;

out:
    g_free();
    free(errormap);
    free(old_snap_name);
    backy_rbd_disconnect(&conn);
    exit(ret);
}
