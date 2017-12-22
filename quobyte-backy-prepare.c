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

#define OBJ_IS_ALLOCATED(i) (bitmap[i / 8] & (1 << (i % 8)))

static void dump_version(FILE *fp, uint64_t *version, int count) {
    int i;
    fprintf(fp, "[ ");
    for (i = 0; i < count; i++) {
         fprintf(fp, "%s%lu" , i ? ", " : "", version[i]);
    }
    fprintf(fp, " ]");
}

int main(int argc, char** argv) {
    long i;
    int ret, num_changed, obj_size, storage_files;
    char *bitmap = NULL, *input = NULL;
    uint64_t obj_count;
    uint64_t *cur_version = NULL, *min_version = NULL;
    char dedup_hash[DEDUP_MAC_SIZE_STR], file_id[256];
    size_t bitmap_sz, file_id_sz;
    struct stat st;
    FILE *log = stderr, *fp = NULL;
    int recovery_mode, verify_mode, interactive_mode = 0;
    struct timespec tstart={}, tend={};
    char *arg_path, *arg_new, *arg_old, *arg_sw;
    struct quobyte_fh* fh = NULL;

    if (argc < 4 && argc != 2) {
        fprintf(log, "Usage: %s <registry> <path> <backy-json> [<backy-json-src> [-r|-v]]\n", argv[0]);
        fprintf(log, "Usage: %s <registry>\n", argv[0]);
        exit(1);
    }

    if (argc == 2) {
        interactive_mode = 1;
        log = stdout;
        fprintf(log, "INTERACTIVE MODE\n");
    }

    pthread_mutex_init(&log_mutex, NULL);

    if (g_arg0 = strrchr(argv[0], '/'))
        g_arg0++;
    else
        g_arg0 = argv[0];

    fprintf(log, "connecting to quobyte registry %s...\n", argv[1]);
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    quobyte_create_adapter(argv[1]);
    clock_gettime(CLOCK_MONOTONIC, &tend);
    fprintf(log, "quobyte_create_adapter took about %.5f seconds\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
    fflush(log);

again:
    ret = 1;
    num_changed = obj_size = storage_files = 0;
    recovery_mode = verify_mode = 0;
    arg_path = arg_new = arg_old = arg_sw = NULL;
    if (interactive_mode) {
        enum { kMaxArgs = 64 };
        int myargc = 0;
        char *myargv[kMaxArgs];
        input = readline("quobyte-backy-prepare> ");
        if (!input) goto out;
        if (!strcmp("", input)) {
            ret = 0;
            goto out;
        }
        if (!strcmp("quit", input)) {
            ret = -1;
            goto out;
        }
        add_history(input);
        char *p2 = strtok(input, " ");
        while (p2 && myargc < kMaxArgs-1)
        {
            myargv[myargc++] = p2;
            p2 = strtok(0, " ");
        }
        myargv[myargc] = 0;
        //~ int i;
        //~ for (i = 0; i < myargc; i++) fprintf(log, "myargv[%d] = '%s'\n", i, myargv[i]);
        if (myargc < 2) {
            goto out;
        }
        arg_path = myargv[0];
        arg_new = myargv[1];
        if (myargc > 2) arg_old = myargv[2];
        if (myargc > 3) arg_sw = myargv[3];
    } else {
        arg_path = argv[2];
        arg_new = argv[3];
        if (argc > 4) arg_old = argv[4];
        if (argc > 5) arg_sw = argv[5];
    }

    clock_gettime(CLOCK_MONOTONIC, &tstart);
    fh = quobyte_open(arg_path, O_RDONLY | O_DIRECT, 0600);
    if (!fh) {
      fprintf(log, "file %s open: %s (%d)\n", arg_path, strerror(errno), errno);
      goto out;
    }
    clock_gettime(CLOCK_MONOTONIC, &tend);
    fprintf(log, "quobyte_open took about %.5f seconds\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
    fflush(log);

    clock_gettime(CLOCK_MONOTONIC, &tstart);
    if ((file_id_sz = quobyte_getxattr(arg_path, "quobyte.file_id", &file_id[0], sizeof(file_id))) < 0) {
      fprintf(log, "file %s could not retrieve quobyte.file_id: %s (%d)\n", arg_path, strerror(errno), errno);
      goto out;
    }
    file_id[file_id_sz] = 0;
    clock_gettime(CLOCK_MONOTONIC, &tend);
    fprintf(log, "quobyte_getxattr took about %.5f seconds\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
    fprintf(log, "quobyte.file_id is %s\n", &file_id[0]);
    fflush(log);

    clock_gettime(CLOCK_MONOTONIC, &tstart);
    assert(!quobyte_fstat(fh, &st));
    clock_gettime(CLOCK_MONOTONIC, &tend);
    fprintf(log, "quobyte_fstat took about %.5f seconds\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
    fflush(log);
    size_t filesize = st.st_size;
    fprintf(log, "filesize is %lu bytes\n", filesize);
    obj_size = quobyte_get_object_size(fh);
    assert(obj_size > 0);
    fprintf(log, "objectsize is %u bytes\n", obj_size);
    storage_files = quobyte_get_number_of_storage_files(fh);
    assert(storage_files > 0);
    fprintf(log, "number of storage files is %d\n", storage_files);
    min_version = calloc(storage_files, sizeof(uint64_t));
    cur_version = calloc(storage_files, sizeof(uint64_t));
    assert(min_version && cur_version);
    obj_count = (filesize + obj_size - 1) / obj_size;
    fprintf(log, "number of objects = %lu\n", obj_count);

    if (arg_old) {
        json_value* value;
        int fd = open(arg_old, O_RDONLY, 0);
        if (!fd) {
           fprintf(log, "fopen %s failed: %s\n", arg_old, strerror(errno));
           goto out;
        }
        clock_gettime(CLOCK_MONOTONIC, &tstart);
        if (parse_json(fd)) {
           fprintf(log, "cant json parse: %s\n", arg_old);
           goto out;
        }
        clock_gettime(CLOCK_MONOTONIC, &tend);
        fprintf(log, "parse_json took about %.5f seconds\n",
               ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
               ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
        fflush(log);
        close(fd);
        assert(g_block_size == obj_size);
        assert(g_filesize <= filesize);
        assert(g_block_count <= obj_count);
        assert(g_version == 2);
        assert(g_metadata);

        value = json_parse((json_char*) g_metadata, strlen(g_metadata));

        if (!value || value->type != json_object) {
            fprintf(log, "json metadata parse error\n");
            json_value_free(value);
            goto out;
        }

        for (i = 0; i < value->u.object.length; i++) {
            json_char *name = value->u.object.values[i].name;
            json_value *val = value->u.object.values[i].value;
            if (!strcmp(name, "quobyte_file_version")) {
                int j;
                vdie_if_n(val->type != json_array, "json parser error: quobyte_file_version has unexpected type (%d)\n", val->type);
                assert(val->u.array.length <= storage_files);
                for (j = 0; j < val->u.array.length; j++) {
                    json_value *entry = val->u.array.values[j];
                    vdie_if_n(entry->type != json_integer, "json parser error: quobyte_file_version entry unexpected type (%d)\n", entry->type);
                    assert(entry->u.integer >= 0);
                    min_version[j] = entry->u.integer;
                }
            } else if (!strcmp(name, "quobyte_file_id")) {
                vdie_if_n(val->type != json_string, "json parser error: quobyte_file_id has unexpected type (%d)\n", val->type);
                vdie_if_n(val->u.string.length != strlen(&file_id[0]) || strncmp(&file_id[0], val->u.string.ptr, strlen(&file_id[0])), "quobyte_file in metadata does not match: '%s' != '%s'\n", val->u.string, &file_id[0]);
            }
        }
        json_value_free(value);
    }
    if (obj_count > g_block_count) {
        fprintf(log, "object count increased from %lu to %lu\n", g_block_count, obj_count);
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
        fprintf(log, "filesize increased from %lu to %lu\n", g_filesize, filesize);
        g_filesize = filesize;
    }
    bitmap_sz = (obj_count + 7) / 8;
    bitmap = calloc(1, bitmap_sz);
    assert(bitmap);
    fprintf(log, "min version = ");
    dump_version(log, min_version, storage_files);
    fprintf(log, "\n");
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    ret = quobyte_get_changed_objects(fh, min_version, cur_version, storage_files, bitmap, bitmap_sz);
    if (ret < 0) {
        fprintf(log, "quobyte_get_changed_objects: %s (%d)\n", strerror(errno), errno);
        goto out;
    }
    clock_gettime(CLOCK_MONOTONIC, &tend);
    fprintf(log, "quobyte_get_changed_objects took about %.5f seconds\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
    fflush(log);
    fprintf(log, "number of objects (ret) = %d\n", ret);
    fprintf(log, "cur version = ");
    dump_version(log, cur_version, storage_files);
    fprintf(log, "\n");

    if (arg_sw) {
        const char *recovery_sw = "-r";
        const char *verify_sw = "-v";
        if (!strncmp(arg_sw, recovery_sw, strlen(recovery_sw))) {
            recovery_mode = 1;
            fprintf(log, "RECOVERY MODE selected\n");
        } else if (!strncmp(arg_sw, verify_sw, strlen(verify_sw))) {
            verify_mode = 1;
            fprintf(log, "VERIFY ALL selected\n");
        }
    }

    for (i = 0; i < obj_count; i++) {
         if (!interactive_mode && !(i % 64)) fprintf(log, "\n");
         if (OBJ_IS_ALLOCATED(i)) {
             if (!recovery_mode) memset(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
             num_changed++;
             if (!interactive_mode) fprintf(log, "X");
         } else {
             if (recovery_mode) memset(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
             if (!interactive_mode) fprintf(log, ".");
         }
    }
    if (!interactive_mode) fprintf(log, "\n\n");
    fprintf(log, "number of changed objects = %d\n", num_changed);

    if (verify_mode) {
        char *buf = malloc(obj_size);
        char h[DEDUP_MAC_SIZE_BYTES];
        assert(buf);
        for (i = 0; i < obj_count; i++) {
            if (!OBJ_IS_ALLOCATED(i)) {
                fprintf(log, "verify if object #%ld is matches csum -> ", i);
                ret = quobyte_read(fh, buf, i * obj_size, obj_size);
                fprintf(log, "ret %d ", ret);
                assert(ret >= 0);
                mmh3(buf, ret, 0, &h[0]);
                assert(!memcmp(&h[0], g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, DEDUP_MAC_SIZE_BYTES));
                fprintf(log, "(OK)\n");
            }
        }
        free(buf);
    }

    fp = fopen(arg_new, "w");
    if (!fp) {
        fprintf(log, "fopen failed: %s\n", arg_new);
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

    fprintf(log, "\nDONE backy backup job json written to: %s\n", arg_new);
    ret = 0;

out:
    free(bitmap);
    bitmap = NULL;
    free(input);
    input = NULL;
    free(cur_version);
    cur_version = NULL;
    free(min_version);
    min_version = NULL;
    g_free();
    if (fp) {
        fclose(fp);
        fp = NULL;
    }
    if (fh) {
        clock_gettime(CLOCK_MONOTONIC, &tstart);
        quobyte_close(fh);
        clock_gettime(CLOCK_MONOTONIC, &tend);
        fprintf(log, "quobyte_close took about %.5f seconds\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
        fflush(log);
        fh = NULL;
    }
    if (interactive_mode) {
        fprintf(log, "quobyte-backy-prepare: ret = %d\n", ret >= 0 ? ret : 0);
        fflush(log);
        if (ret >= 0) goto again;
    }
    quobyte_destroy_adapter();
    fclose(log);
    exit(ret > 0 ? : 0);
}
