#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include "backy.h"

int main(int argc, char** argv) {
    char dedup_hash[DEDUP_MAC_SIZE_STR];
    FILE *log = stderr, *fp = NULL;
    const char *testfile = "/tmp/test.json";
    long i;
    uint64_t objcount = 1 << 19;
    struct timespec tstart={}, tend={};
    int ret = 0;

    g_block_mapping = malloc((DEDUP_MAC_SIZE_BYTES) * objcount);

	clock_gettime(CLOCK_MONOTONIC, &tstart);

    fp = fopen(testfile, "w");
    if (!fp) {
        fprintf(log, "fopen failed: %s\n", testfile);
        goto out;
    }

    fprintf(fp, "{\n");
    fprintf(fp, " \"version\" : 2,\n");
    fprintf(fp, " \"hash\" : \"%s\",\n", DEDUP_MAC_NAME);
    fprintf(fp, " \"blocksize\" : %u,\n", 1 << 20);
    fprintf(fp, " \"mapping\" : {");
    for (i = 0; i < objcount; i++) {
         dedup_hash_sprint(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, &dedup_hash[0]);
         fprintf(fp, "%s\"%lu\":\"%s\"", i ? "," : "", i, dedup_hash);
    }
    fprintf(fp, "},\n");
    fprintf(fp, " \"size\" : %" PRIu64 "\n", objcount * 1048576);
    fprintf(fp, "}\n");

	clock_gettime(CLOCK_MONOTONIC, &tend);
	fprintf(log, "write_json took about %.5f seconds\n",
		   ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
		   ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));

	fclose(fp);
	fp = NULL;
	g_free();

	int fd = open(testfile, O_RDONLY, 0);
	if (fd < 0) {
		fprintf(log, "fopen %s failed: %s\n", testfile, strerror(errno));
		goto out;
	}
	clock_gettime(CLOCK_MONOTONIC, &tstart);
	if (parse_json(fd)) {
	   fprintf(log, "cant json parse: %s\n", testfile);
	   goto out;
	}
	clock_gettime(CLOCK_MONOTONIC, &tend);
	fprintf(log, "parse_json took about %.5f seconds\n",
		   ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
		   ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
	fflush(log);
	close(fd);

    ret = 0;

out:
    g_free();
    if (fp) {
        fclose(fp);
        fp = NULL;
    }
    exit(ret);
}
