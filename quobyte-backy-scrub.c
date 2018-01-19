#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <quobyte.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "backy.h"
#include "quobyte-backy.h"

int main(int argc, char** argv) {
	int fd = 0, ret = 1;
	long changed_api = 0, changed_csum = 0;
	long i;
	FILE *log = stderr;
	struct qb_connection qb = {};
	char *errormap = NULL;

	if (argc < 4) {
		fprintf(log, "Usage: %s <registry> <path> <backy-json> [<fpath>]\n", argv[0]);
		exit(1);
	}

	pthread_mutex_init(&log_mutex, NULL);

	qb_create_adapter(log, argv[1]);
	if (qb_open_file(log, &qb, argv[2])) {
		goto out;
	}
    
	if (qb_parse_json(log, &qb, argv[3])) {
		goto out;
	};

	if (qb.filesize != g_filesize) {
		fprintf(log, "SKIP: filesize changed from %lu to %lu", g_filesize, qb.filesize);
		ret = 3;
		goto out;
	}

	errormap = calloc(1, qb.bitmap_sz);
	assert(errormap);

	char *buf = malloc(qb.obj_size);
	char h[DEDUP_MAC_SIZE_BYTES];
	assert(buf);
	if (argc == 5) {
		fd = open(argv[4], O_RDONLY, 0);
		if (fd < 0) {
			fprintf(log, "fopen %s failed: %s\n", argv[4], strerror(errno));
			goto out;
		}
	}
	for (i = 0; i < qb.obj_count; i++) {
		if (fd) {
			ret = read(fd, buf, qb.obj_size);
		} else {
			ret = quobyte_read(qb.fh, buf, i * qb.obj_size, qb.obj_size);
		}
		assert(ret >= 0);
		fprintf(log, "progress: %lu bytes read\n", i * qb.obj_size);
		mmh3(buf, ret, 0, &h[0]);
		if (memcmp(&h[0], g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, DEDUP_MAC_SIZE_BYTES)) {
			OBJ_SET_ALLOCATED(errormap, i);
		}
	}
	if (fd) {
		close(fd);
	}
	free(buf);

	if (qb_get_changed_objects(log, &qb) < 0) {
		goto out;
	}

	for (i = 0; i < qb.obj_count; i++) {
		if (OBJ_IS_ALLOCATED(errormap, i) && !OBJ_IS_ALLOCATED(qb.bitmap, i)) {
			fprintf(log, "FATAL ERROR: object #%lu failed checksum test, but is not marked as changed\n", i);
			ret = 2;
			goto out;
		}
		if (OBJ_IS_ALLOCATED(errormap, i)) changed_csum++;
		if (OBJ_IS_ALLOCATED(qb.bitmap, i)) changed_api++;
	}

	fprintf(log, "OK: all objects passed scrubbing test. changed_api: %lu changed_csum: %lu\n", changed_api, changed_csum);

	ret = 0;
out:
	g_free();
	free(errormap);
	qb_close_file(log, &qb);
	quobyte_destroy_adapter();
	fclose(log);
	exit(ret > 0 ? : 0);
}
