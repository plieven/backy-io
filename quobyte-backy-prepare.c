#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <quobyte.h>

#include "backy.h"

#define OBJ_IS_ALLOCATED(i) (bitmap[i / 8] & (1 << (i % 8)))
#define OBJ_SIZE (8 * 1024 * 1024)

int main(int argc, char** argv) {
    long i;
    int ret = 1, num_changed = 0;
    char *block_mapping = NULL, *bitmap = NULL, *zeroblock = NULL;
    uint64_t obj_count, cur_version, min_version = 0;
    char zeroblock_hash[DEDUP_MAC_SIZE_BYTES], dedup_hash[DEDUP_MAC_SIZE_STR];
    size_t bitmap_sz;
    struct stat st;
    FILE *fp = stdout;
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <registry> <path> <backy-json> [<backy-json-src>]\n", argv[0]);
        exit(1);
    }
    quobyte_create_adapter(argv[1]);
    struct quobyte_fh* fh = quobyte_open(argv[2], O_RDONLY | O_DIRECT, 0600);
    if (!fh) {
      fprintf(stderr, "file %s open: %s (%d)\n", argv[2], strerror(errno), errno);
      goto out;
    }
    
    assert(!quobyte_fstat(fh, &st));
    size_t filesize = st.st_size;
   
    fprintf(stderr, "filesize is %lu bytes\n", filesize);
    fprintf(stderr, "objectsize is %u bytes\n", OBJ_SIZE);
    obj_count = (filesize + OBJ_SIZE - 1) / OBJ_SIZE;
    fprintf(stderr, "number of objects = %lu\n", obj_count);

    block_mapping = malloc(obj_count * DEDUP_MAC_SIZE_BYTES);
    assert(block_mapping);
    zeroblock = calloc(1, OBJ_SIZE);
    assert(zeroblock);
    mmh3(zeroblock, OBJ_SIZE, 0, &zeroblock_hash[0]);
    free(zeroblock);
    for (i = 0; i < obj_count; i++) {
        memcpy(block_mapping + i * DEDUP_MAC_SIZE_BYTES, &zeroblock_hash[0], DEDUP_MAC_SIZE_BYTES);
    }

    bitmap_sz = (obj_count + 7) / 8;
    bitmap = calloc(1, bitmap_sz);
    assert(bitmap);
    fprintf(stderr, "min version = %lu\n", min_version);
    ret = quobyte_get_changed_objects(fh, min_version, &cur_version, bitmap, bitmap_sz);
    if (ret < 0) {
        fprintf(stderr, "quobyte_get_changed_objects: %s (%d)\n", strerror(errno), errno);
        quobyte_close(fh);
        quobyte_destroy_adapter();
        exit(1);
    }
    fprintf(stderr, "number of objects (ret) = %d\n", ret);
    fprintf(stderr, "current version = %lu\n", cur_version);
    for (i = 0; i < obj_count; i++) {
         if (!(i % 64)) fprintf(stderr, "\n");
         if (OBJ_IS_ALLOCATED(i)) {
             memset(block_mapping + i * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
             num_changed++;
             fprintf(stderr, "X");
         } else {
             fprintf(stderr, ".");
         }
    }
    fprintf(stderr, "\n\n");
    fprintf(stderr, "number of changed objects = %d\n", num_changed);

    fp = fopen(argv[3], "w");
    if (!fp) {
        fprintf(stderr, "fopen failed: %s\n", argv[3]);
        goto out;
    }

    fprintf(fp, "{\n");
    fprintf(fp, " \"version\" : 2,\n");
    fprintf(fp, " \"hash\" : \"%s\",\n", DEDUP_MAC_NAME);
    fprintf(fp, " \"blocksize\" : %u,\n", OBJ_SIZE);
    fprintf(fp, " \"mapping\" : {");
    for (i = 0; i < obj_count; i++) {
         dedup_hash_sprint(block_mapping + i * DEDUP_MAC_SIZE_BYTES, &dedup_hash[0]);
         fprintf(fp, "%s\n  \"%lu\" : \"%s\"", i ? "," : "", i, dedup_hash);
    }
    fprintf(fp, "\n },\n");
    fprintf(fp, " \"metadata\" : {\n");
    fprintf(fp, "  \"quobyte_registry\": \"%s\",\n", argv[1]);
    fprintf(fp, "  \"quobyte_file\": \"%s\",\n", argv[2]);
    fprintf(fp, "  \"quobyte_file_version\": %lu", cur_version);
    fprintf(fp, "\n },\n");
    fprintf(fp, " \"size\" : %lu\n", filesize);
    fprintf(fp, "}\n");

    fprintf(stderr, "\nDONE backy backup job json written to: %s\n", argv[3]);
    ret = 0;
out:
    free(bitmap);
    free(block_mapping);
    if (fh) quobyte_close(fh);
    quobyte_destroy_adapter();
    fclose(fp);
    exit(ret);
}
