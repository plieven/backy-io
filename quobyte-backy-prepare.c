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

void dump_version(FILE *fp, uint64_t *version, int count) {
    int i;
    fprintf(fp, "{ ");
    for (i = 0; i < count; i++) {
         fprintf(fp, "%s%lu" , i ? ", " : "", version[i]);
    }
    fprintf(fp, " }");
}

int main(int argc, char** argv) {
    long i;
    int ret = 1, num_changed = 0, obj_size = 0, storage_files = 0;
    char *bitmap = NULL;
    uint64_t obj_count;
    uint64_t *cur_version = NULL, *min_version = NULL;
    char dedup_hash[DEDUP_MAC_SIZE_STR], file_id[256];
    size_t bitmap_sz;
    struct stat st;
    FILE *fp = stdout;
    int recovery_mode = 0, verify_mode = 0;
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <registry> <path> <backy-json> [<backy-json-src> [-r|-v]]\n", argv[0]);
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

    if (quobyte_getxattr(argv[2], "quobyte.file_id", &file_id[0], sizeof(file_id)) < 0) {
      fprintf(stderr, "file %s could not retrieve quobyte.file_id: %s (%d)\n", argv[2], strerror(errno), errno);
      goto out;
    }
    fprintf(stderr, "quobyte.file_id is %s\n", &file_id[0]);

    assert(!quobyte_fstat(fh, &st));
    size_t filesize = st.st_size;
    fprintf(stderr, "filesize is %lu bytes\n", filesize);
    obj_size = quobyte_get_object_size(fh);
    assert(obj_size > 0);
    fprintf(stderr, "objectsize is %u bytes\n", obj_size);
    storage_files = quobyte_get_number_of_storage_files(fh);
    assert(storage_files > 0);
    fprintf(stderr, "number of storage files is %d\n", storage_files);
    min_version = calloc(storage_files, sizeof(uint64_t));
    cur_version = calloc(storage_files, sizeof(uint64_t));
    assert(min_version && cur_version);
    obj_count = (filesize + obj_size - 1) / obj_size;
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
        assert(g_block_size == obj_size);
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
                int j, cnt = 0;
                i++;
                vdie_if_n((tok + i)->type != JSMN_OBJECT, "json parser error: quobyte_file_version has unexpected type (%d)\n", (tok + i)->type);
                cnt = (tok + i)->size;
                assert(cnt <= storage_files);
                i++;
                for (j = i; j < i + cnt; j++) {
                    min_version[j-i] = strtol(g_metadata + (tok + j)->start, NULL, 0);
                }
                i = j - 1;
            } else if (jsoneq(g_metadata, tok + i, "quobyte_file_id") == 0) {
                i++;
                vdie_if_n((tok + i)->end - (tok + i)->start != strlen(&file_id[0]) || strncmp(&file_id[0], g_metadata + (tok + i)->start, strlen(&file_id[0])), "quobyte_file in metadata does not match: '%.*s' != '%s'\n", (tok + i)->end - (tok + i)->start, g_metadata + (tok + i)->start, &file_id[0]);
            }
        }
        assert(min_version);
        free(tok);
    }
    if (obj_count > g_block_count) {
        fprintf(stderr, "object count increased from %lu to %lu\n", g_block_count, obj_count);
        g_block_mapping = realloc(g_block_mapping, obj_count * DEDUP_MAC_SIZE_BYTES);
        assert(g_block_mapping);
        g_zeroblock = calloc(1, obj_size);
        assert(g_zeroblock);
        mmh3(g_zeroblock, obj_size, 0, &g_zeroblock_hash[0]);
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
    fprintf(stderr, "min version = ");
    dump_version(stderr, min_version, storage_files);
    fprintf(stderr, "\n");
    ret = quobyte_get_changed_objects(fh, min_version, cur_version, storage_files, bitmap, bitmap_sz);
    if (ret < 0) {
        fprintf(stderr, "quobyte_get_changed_objects: %s (%d)\n", strerror(errno), errno);
        goto out;
    }
    fprintf(stderr, "number of objects (ret) = %d\n", ret);
    fprintf(stderr, "cur version = ");
    dump_version(stderr, cur_version, storage_files);
    fprintf(stderr, "\n");

    if (argc > 5) {
        const char *recovery_sw = "-r";
        const char *verify_sw = "-v";
        if (!strncmp(argv[5], recovery_sw, strlen(recovery_sw))) {
            recovery_mode = 1;
            fprintf(stderr, "RECOVERY MODE selected\n");
        } else if (!strncmp(argv[5], verify_sw, strlen(verify_sw))) {
            verify_mode = 1;
            fprintf(stderr, "VERIFY ALL selected\n");
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

    if (verify_mode) {
        char *buf = malloc(obj_size);
        char h[DEDUP_MAC_SIZE_BYTES];
        assert(buf);
        for (i = 0; i < obj_count; i++) {
            if (!OBJ_IS_ALLOCATED(i)) {
                fprintf(stderr, "verify if object #%ld is matches csum -> ", i);
                ret = quobyte_read(fh, buf, i * obj_size, obj_size);
                fprintf(stderr, "ret %d ", ret);
                assert(ret >= 0);
                mmh3(buf, ret, 0, &h[0]);
                assert(!memcmp(&h[0], g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, DEDUP_MAC_SIZE_BYTES));
                fprintf(stderr, "(OK)\n");
            }
        }
        free(buf);
    }

    fp = fopen(argv[3], "w");
    if (!fp) {
        fprintf(stderr, "fopen failed: %s\n", argv[3]);
        goto out;
    }

    fprintf(fp, "{\n");
    fprintf(fp, " \"version\" : 2,\n");
    fprintf(fp, " \"hash\" : \"%s\",\n", DEDUP_MAC_NAME);
    fprintf(fp, " \"blocksize\" : %u,\n", obj_size);
    fprintf(fp, " \"mapping\" : {");
    for (i = 0; i < obj_count; i++) {
         dedup_hash_sprint(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, &dedup_hash[0]);
         fprintf(fp, "%s\n  \"%lu\" : \"%s\"", i ? "," : "", i, dedup_hash);
    }
    fprintf(fp, "\n },\n");
    if (!recovery_mode) {
        fprintf(fp, " \"metadata\" : {\n");
        fprintf(fp, "  \"quobyte_file_id\": \"%s\",\n", &file_id[0]);
        fprintf(fp, "  \"quobyte_file_version\": ");
        dump_version(fp, cur_version, storage_files);
        fprintf(fp, "\n },\n");
    }
    fprintf(fp, " \"size\" : %lu\n", filesize);
    fprintf(fp, "}\n");

    fprintf(stderr, "\nDONE backy backup job json written to: %s\n", argv[3]);
    ret = 0;
out:
    free(bitmap);
    free(cur_version);
    free(min_version);
    g_free();
    if (fh) quobyte_close(fh);
    quobyte_destroy_adapter();
    fclose(fp);
    exit(ret);
}
