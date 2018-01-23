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

#define MAX_CONNECTIONS 1

int main(int argc, char** argv) {
    long i;
    int ret, num_changed;
    char *input = NULL;
    char dedup_hash[DEDUP_MAC_SIZE_STR];
    FILE *log = stderr, *fp = NULL;
    int recovery_mode, interactive_mode = 0;
    char *arg_path, *arg_new, *arg_old, *arg_sw;
    int size_changed = 0, num_connections = 0;
    struct qb_connection qbconns[MAX_CONNECTIONS] = {0};
    struct qb_connection *qb;

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

    qb_create_adapter(log, argv[1]);

again:
    ret = 1;
    num_changed = 0;
    recovery_mode = 0;
    arg_path = arg_new = arg_old = arg_sw = NULL;
    if (interactive_mode) {
        enum { kMaxArgs = 64 };
        int myargc = 0;
        char *myargv[kMaxArgs];
        input = readline("quobyte-backy-prepare> ");
        if (!input || !strcmp("quit", input)) {
            ret = -1;
            goto out;
        }
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

    qb = NULL;
    for (i = 0; i < num_connections; i++) {
         if (!strcmp(qbconns[i].path, arg_path)) {
             qb = &qbconns[i];
             fprintf(log, "using cached connection to %s!\n", qb->path);
             qb_refresh_file(log, qb);
             break;
         }
    }
    if (!qb) {
        assert(num_connections < MAX_CONNECTIONS);
        if (qb_open_file(log, &qbconns[num_connections], arg_path)) {
            goto out;
        }
        qb = &qbconns[num_connections];
        num_connections++;
    }

    if (arg_sw) {
        const char *recovery_sw = "-r";
        if (!strncmp(arg_sw, recovery_sw, strlen(recovery_sw))) {
            recovery_mode = 1;
            fprintf(log, "RECOVERY MODE selected\n");
        }
    }

    if (arg_old) {
        if (qb_parse_json(log, qb, arg_old)) {
            goto out;
        }
    }

    if (qb->obj_count != g_block_count) {
        fprintf(log, "object count changed from %lu to %lu", g_block_count, qb->obj_count);
        vgotoout_if_n(recovery_mode, "object count is not allowed to change in RECOVERY MODE", 0);
        if (g_filesize % qb->obj_size) {
            /* we have to mark the last block of the old backup as dirty as it will
             * grow to full obj_size if the obj_size does not divide the old filesize. */
            assert(g_block_count > 0);
            memset(g_block_mapping + (g_block_count - 1) * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
        }
        g_block_mapping = realloc(g_block_mapping, qb->obj_count * DEDUP_MAC_SIZE_BYTES);
        assert(g_block_mapping);
        g_zeroblock = calloc(1, qb->obj_size);
        assert(g_zeroblock);
        mmh3(g_zeroblock, qb->obj_size, 0, &g_zeroblock_hash[0]);
        for (i = g_block_count; i < qb->obj_count; i++) {
            memcpy(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, &g_zeroblock_hash[0], DEDUP_MAC_SIZE_BYTES);
        }
        g_block_count = qb->obj_count;
    }

    if (qb->filesize != g_filesize) {
        fprintf(log, "filesize changed from %lu to %lu", g_filesize, qb->filesize);
        vgotoout_if_n(recovery_mode, "filesize is not allowed to change in RECOVERY MODE", 0);
        g_filesize = qb->filesize;
        if (g_filesize % qb->obj_size) {
            /* we have to mark the last block of the new backup as dirty as it will
             * not have full obj_size if the obj_size does not divide the new filesize. */
            memset(g_block_mapping + (g_block_count - 1) * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
        }
        size_changed = 1;
    }

    qb_get_changed_objects(log, qb);

    for (i = 0; i < qb->obj_count; i++) {
         if (!interactive_mode && !(i % 64)) fprintf(log, "\n");
         if (OBJ_IS_ALLOCATED(qb->bitmap, i)) {
             if (!recovery_mode) memset(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
             num_changed++;
             if (!interactive_mode) fprintf(log, "X");
         } else {
             if (recovery_mode) {
                 memset(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
             } else if (size_changed) {
                 char zeromac[DEDUP_MAC_SIZE] = {0};
                 if (!memcmp(zeromac, g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, DEDUP_MAC_SIZE_BYTES)) num_changed++;
             }
             if (!interactive_mode) fprintf(log, ".");
         }
    }
    if (!interactive_mode) fprintf(log, "\n\n");
    fprintf(log, "number of changed objects = %d\n", num_changed);

    fp = fopen(arg_new, "w");
    if (!fp) {
        fprintf(log, "fopen failed: %s\n", arg_new);
        goto out;
    }

    fprintf(fp, "{\n");
    fprintf(fp, " \"version\" : 2,\n");
    fprintf(fp, " \"hash\" : \"%s\",\n", DEDUP_MAC_NAME);
    fprintf(fp, " \"blocksize\" : %u,\n", qb->obj_size);
    fprintf(fp, " \"mapping\" : {");
    for (i = 0; i < qb->obj_count; i++) {
         dedup_hash_sprint(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, &dedup_hash[0]);
         fprintf(fp, "%s\n  \"%lu\" : \"%s\"", i ? "," : "", i, dedup_hash);
    }
    fprintf(fp, "\n },\n");
    if (!recovery_mode) {
        fprintf(fp, " \"metadata\" : {\n");
        fprintf(fp, "  \"quobyte_file_id\": \"%s\",\n", &qb->file_id[0]);
        fprintf(fp, "  \"quobyte_file_version\": ");
        dump_version(fp, qb->cur_version, qb->storage_files);
        fprintf(fp, "\n },\n");
    }
    fprintf(fp, " \"size\" : %lu\n", qb->filesize);
    fprintf(fp, "}\n");

    fprintf(log, "\nDONE backy backup job json written to: %s\n", arg_new);
    ret = 0;

out:
    g_free();
    if (fp) {
        fclose(fp);
        fp = NULL;
    }
    if (interactive_mode) {
        fprintf(log, "quobyte-backy-prepare: ret = %d\n", ret >= 0 ? ret : 0);
        fflush(log);
        if (ret >= 0) goto again;
    }
    for (i = 0; i < num_connections; i++) {
        qb_close_file(log, &qbconns[i]);
    }
    num_connections = 0;
    quobyte_destroy_adapter();
    fclose(log);
    exit(ret > 0 ? : 0);
}
