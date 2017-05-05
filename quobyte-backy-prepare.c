#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <quobyte.h>

#include "backy.h"

#define OBJ_IS_ALLOCATED(i) (bitmap[i / 8] & (1 << (i % 8)))
#define OBJ_SIZE (8 * 1024 * 1024)

int main(int argc, char** argv) {
    long i;
    int ret = 1, num_changed = 0;
    char *bitmap = NULL;
    uint64_t obj_count, cur_version, min_version = 0;
    char dedup_hash[DEDUP_MAC_SIZE_STR];
    size_t bitmap_sz;
    struct stat st;
    FILE *fp = stdout;
    int recovery_mode = 0;
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <registry> <path> <backy-json> [<backy-json-src> [-r|<n>]]\n", argv[0]);
        exit(1);
    }
    pthread_mutex_init(&log_mutex, NULL);

    if (g_arg0 = strrchr(argv[0], '/'))
        g_arg0++;
    else
        g_arg0 = argv[0];

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

    if (argc > 4) {
        jsmn_parser parser;
        jsmntok_t *tok;
        int tokencnt;
        int fd = open(argv[4], O_RDONLY, 0);
        if (!fd) {
           fprintf(stderr, "fopen %s failed: %s\n", argv[4], strerror(errno));
           goto out;
        }
        parse_json(fd);
        close(fd);
        assert(g_block_size == OBJ_SIZE);
        assert(g_filesize <= filesize);
        assert(g_block_count <= obj_count);
        assert(g_version == 2);
        assert(g_metadata);
        jsmn_init(&parser);
        tokencnt = jsmn_parse(&parser, g_metadata, strlen(g_metadata), NULL, 0);

        tok = malloc(sizeof(*tok) * tokencnt);
        die_if(!tok, ESTR_MALLOC);

        jsmn_init(&parser);
        vdie_if_n(tokencnt != jsmn_parse(&parser, g_metadata, strlen(g_metadata), tok, tokencnt), "json parse error", 0);
        for (i = 1; i < tokencnt; i++) {
            if (jsoneq(g_metadata, tok + i, "quobyte_file_version") == 0) {
                i++;
                min_version = strtol(g_metadata + (tok + i)->start, NULL, 0);
            } else if (jsoneq(g_metadata, tok + i, "quobyte_file") == 0) {
                i++;
                vdie_if_n((tok + i)->end - (tok + i)->start != strlen(argv[2]) || strncmp(argv[2], g_metadata + (tok + i)->start, strlen(argv[2])), "quobyte_file in metadata does not match: '%.*s' != '%s'\n", (tok + i)->end - (tok + i)->start, g_metadata + (tok + i)->start, argv[2]);
            } else if (jsoneq(g_metadata, tok + i, "quobyte_registry") == 0) {
                i++;
                vdie_if_n((tok + i)->end - (tok + i)->start != strlen(argv[1]) || strncmp(argv[1], g_metadata + (tok + i)->start, strlen(argv[1])), "quobyte_registry in metadata does not match: '%.*s' != '%s'\n", (tok + i)->end - (tok + i)->start, g_metadata + (tok + i)->start, argv[1]);
            }
        }
        assert(min_version);
        free(tok);
    }
    if (obj_count > g_block_count) {
        fprintf(stderr, "object count increased from %lu to %lu\n", g_block_count, obj_count);
        g_block_mapping = realloc(g_block_mapping, obj_count * DEDUP_MAC_SIZE_BYTES);
        assert(g_block_mapping);
        g_zeroblock = calloc(1, OBJ_SIZE);
        assert(g_zeroblock);
        mmh3(g_zeroblock, OBJ_SIZE, 0, &g_zeroblock_hash[0]);
        for (i = g_block_count; i < obj_count; i++) {
            memcpy(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, &g_zeroblock_hash[0], DEDUP_MAC_SIZE_BYTES);
        }
        g_block_count = obj_count;
    }
    if (filesize > g_filesize) {
        fprintf(stderr, "filesize increased from %lu to %lu\n", g_filesize, filesize);
        g_filesize = filesize;
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

    if (argc > 5) {
        const char *recovery_sw = "-r";
        if (!strncmp(argv[5], recovery_sw, strlen(recovery_sw))) {
            recovery_mode = 1;
            fprintf(stderr, "RECOVERY MODE selected\n");
        }
    }

    for (i = 0; i < obj_count; i++) {
         if (!(i % 64)) fprintf(stderr, "\n");
         if (OBJ_IS_ALLOCATED(i)) {
             if (!recovery_mode) memset(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
             num_changed++;
             fprintf(stderr, "X");
         } else {
             if (recovery_mode) memset(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
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
         dedup_hash_sprint(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, &dedup_hash[0]);
         fprintf(fp, "%s\n  \"%lu\" : \"%s\"", i ? "," : "", i, dedup_hash);
    }
    fprintf(fp, "\n },\n");
    if (!recovery_mode) {
        fprintf(fp, " \"metadata\" : {\n");
        fprintf(fp, "  \"quobyte_registry\": \"%s\",\n", argv[1]);
        fprintf(fp, "  \"quobyte_file\": \"%s\",\n", argv[2]);
        fprintf(fp, "  \"quobyte_file_version\": %lu", cur_version);
        fprintf(fp, "\n },\n");
    }
    fprintf(fp, " \"size\" : %lu\n", filesize);
    fprintf(fp, "}\n");

    fprintf(stderr, "\nDONE backy backup job json written to: %s\n", argv[3]);
    ret = 0;
out:
    free(bitmap);
    g_free();
    if (fh) quobyte_close(fh);
    quobyte_destroy_adapter();
    fclose(fp);
    exit(ret);
}
