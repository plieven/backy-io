#include "backy.h"

#define DEBUG_PREFIX "rbd-backy-scrub"

#include "rbd-backy.h"

int main(int argc, char** argv) {
	int ret = 1;
	long changed_api = 0, changed_csum = 0;
	long i;
	struct rbd_connection conn = {0};
	char *errormap = NULL;
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

	char *buf = malloc(conn.info.obj_size);
	char h[DEDUP_MAC_SIZE_BYTES];
	assert(buf);
    //TODO: use rbd_read_iterate2 ?
    clock_gettime(CLOCK_MONOTONIC, &tstart);
	for (i = 0; i < conn.info.num_objs; i++) {
        ret = rbd_read(conn.image, i * conn.info.obj_size, conn.info.obj_size, buf);
		assert(ret >= 0);
		fprintf(stderr, "progress: %lu bytes read\n", i * conn.info.obj_size);
		mmh3(buf, ret, 0, &h[0]);
		if (memcmp(&h[0], g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, DEDUP_MAC_SIZE_BYTES)) {
			OBJ_SET_ALLOCATED(errormap, i);
		}
	}
    clock_gettime(CLOCK_MONOTONIC, &tend);
    fprintf(stderr, "rbd_backy_scrub (read of complete image) took about %.5f seconds\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
	free(buf);

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
        //TODO: refactor first 2 ifs
		if (OBJ_IS_ALLOCATED(errormap, i) && OBJ_IS_ALLOCATED(conn.alloc_bitmap, i) && !OBJ_IS_ALLOCATED(conn.change_bitmap, i)) {
			char dedup_hash[DEDUP_MAC_SIZE_STR] = {};
			fprintf(stderr, "FATAL ERROR: object #%lu failed checksum test, but is not marked as changed\n", i);
			dedup_hash_sprint(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, &dedup_hash[0]);
			fprintf(stderr, "FATAL ERROR: object #%lu hash on backup: %s\n", i, dedup_hash);
			ret = 2;
			goto out;
		}
		if (OBJ_IS_ALLOCATED(conn.alloc_bitmap, i) && OBJ_IS_ALLOCATED(errormap, i)) changed_csum++;
		if (OBJ_IS_ALLOCATED(conn.change_bitmap, i)) changed_api++;
	}

	fprintf(stderr, "SUCCESS: all objects passed scrubbing test. changed_api: %lu changed_csum: %lu\n", changed_api, changed_csum);

	ret = 0;

out:
    g_free();
    free(errormap);
    free(old_snap_name);
    backy_rbd_disconnect(&conn);
    exit(ret);
}
