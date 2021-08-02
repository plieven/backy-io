#include "backy.h"

#define DEBUG_PREFIX "rbd-backy-prepare"

#include "rbd-backy.h"

int main(int argc, char** argv) {
    int ret = 1;
    long r, i, num_changed = 0, num_allocated = 0, mapping_count = 0;
    struct rbd_connection conn = {0};
    struct timespec tstart={}, tend={};
    char dedup_hash[DEDUP_MAC_SIZE_STR] = {};
    int recovery_mode = 0;
    int size_changed = 0;
    FILE *fp;

    time_t since = 0;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <rbd-path> <backy-json> [<backy-json-src> [-r|-t]]\n", argv[0]);
        exit(1);
    }

    char *arg_path = argv[1];
    char *arg_new = argv[2];
    char *arg_old = argv[3];
    char *arg_sw = argv[4];

    r = backy_rbd_connect(arg_path, &conn);
    if (r) {
        fprintf(stderr, "backy_rbd_connect: %s (%s)", arg_path, strerror(errno));
        exit(1);
    }

    if (argc > 3 && arg_old) {
        if (rbd_parse_json(&conn, arg_old, &since)) {
            goto out;
        }
        fprintf(stderr, "old snapshot was created: %ld\n", since);
    } else {
        g_version = 3;
        g_block_size = conn.info.obj_size;
    }

    if (argc > 4 && arg_sw) {
        if (!strcmp(arg_sw, "-t")) {
            since = 0;
        } else if (!strcmp(arg_sw, "-r")) {
            recovery_mode = 1;
        } else {
            fprintf(stderr, "cannot handle switch: %s\n", arg_sw);
            goto out;
        }
    }

    if (conn.info.num_objs != g_block_count) {
        fprintf(stderr, "object count changed from %lu to %lu\n", g_block_count, conn.info.num_objs);
        vgotoout_if_n(recovery_mode, "object count is not allowed to change in RECOVERY MODE", 0);
        if (g_filesize % conn.info.obj_size) {
            /* we have to mark the last block of the old backup as dirty as it will
             * grow to full obj_size if the obj_size does not divide the old filesize. */
            assert(g_block_count > 0);
            memset(g_block_mapping + (g_block_count - 1) * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
        }
        g_block_mapping = realloc(g_block_mapping, conn.info.num_objs * DEDUP_MAC_SIZE_BYTES);
        assert(g_block_mapping);
        init_zero_block();
        for (i = g_block_count; i < conn.info.num_objs; i++) {
            memcpy(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, &g_zeroblock_hash[0], DEDUP_MAC_SIZE_BYTES);
        }
        g_block_count = conn.info.num_objs;
    }

    if (conn.info.size != g_filesize) {
        fprintf(stderr, "filesize changed from %lu to %lu\n", g_filesize, conn.info.size);
        vgotoout_if_n(recovery_mode, "filesize is not allowed to change in RECOVERY MODE", 0);
        g_filesize = conn.info.size;
        if (g_filesize % conn.info.obj_size) {
            /* we have to mark the last block of the new backup as dirty as it will
             * not have full obj_size if the obj_size does not divide the new filesize. */
            memset(g_block_mapping + (g_block_count - 1) * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
        }
        size_changed = 1;
    }

    r = backy_rbd_changed_objs(&conn, since, NULL);
    assert (r>=0);

    init_zero_block();

    if (!recovery_mode) {
        for (i = 0; i < conn.info.num_objs; i++) {
            if (OBJ_IS_ALLOCATED(conn.alloc_bitmap, i)) {
                num_allocated++;
                if (OBJ_IS_ALLOCATED(conn.change_bitmap, i)) {
                    num_changed++;
                    memset(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
                }
            } else {
                memcpy(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, g_zeroblock_hash, DEDUP_MAC_SIZE_BYTES);
            }
        }
    } else {
        /* recovery mode */
        for (i = 0; i < conn.info.num_objs; i++) {
            if (OBJ_IS_ALLOCATED(conn.alloc_bitmap, i)) {
                num_allocated++;
                if (!OBJ_IS_ALLOCATED(conn.change_bitmap, i)) {
                    memset(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
                } else {
                    num_changed++;
                }
            } else {
                if (dedup_is_zero_chunk(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES)) {
                    memset(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
                } else {
                    num_changed++;
                }
            }
        }
    }

    if (conn.info.num_objs * conn.info.obj_size > conn.info.size) {
        fprintf(stderr, "last object #%ld exceeds the end of image, forcefully setting it to changed\n", conn.info.num_objs - 1);
        memset(g_block_mapping + (conn.info.num_objs - 1) * DEDUP_MAC_SIZE_BYTES, 0x00, DEDUP_MAC_SIZE_BYTES);
        num_changed++;
    }

    fprintf(stderr, "number of allocated objects = %ld\n", num_allocated);
    fprintf(stderr, "number of changed objects = %ld\n", num_changed);
    fprintf(stderr, "filesize is %lu bytes\n", conn.info.size);
    fprintf(stderr, "objectsize is %lu bytes\n", conn.info.obj_size);
    fprintf(stderr, "rbd.id is %s\n", conn.id);

    clock_gettime(CLOCK_MONOTONIC, &tstart);
    fp = fopen(arg_new, "w");
    if (!fp) {
        fprintf(stderr, "fopen failed: %s\n", arg_new);
        goto out;
    }

    fprintf(fp, "{\n");
    fprintf(fp, " \"version\" : %d,\n", g_version);
    fprintf(fp, " \"hash\" : \"%s\",\n", DEDUP_MAC_NAME);
    fprintf(fp, " \"blocksize\" : %lu,\n", conn.info.obj_size);
    fprintf(fp, " \"mapping\" : {");
    for (i = 0; i < conn.info.num_objs; i++) {
        if (g_version < 3 || !dedup_is_zero_chunk(&g_block_mapping[i * DEDUP_MAC_SIZE_BYTES])) {
            dedup_hash_sprint(g_block_mapping + i * DEDUP_MAC_SIZE_BYTES, &dedup_hash[0]);
            fprintf(fp, "%s\"%lu\":\"%s\"", mapping_count++ ? "," : "", i, dedup_hash);
        }
    }
    fprintf(fp, "},\n");
    if (!recovery_mode) {
        fprintf(fp, " \"metadata\" : {\n");
        fprintf(fp, "  \"rados_cluster_fsid\": \"%s\",\n", conn.fsid);
        fprintf(fp, "  \"rbd_path\": \"%s\",\n", arg_path);
        fprintf(fp, "  \"rbd_id\": \"%s\",\n", conn.id);
        if (conn.snap_id) {
            fprintf(fp, "  \"rbd_snap_timestamp\": %ld,\n", conn.snap_timestamp.tv_sec);
            fprintf(fp, "  \"rbd_snap_name\": \"%s\",\n", conn.snap_name);
        }
        fprintf(fp, "  \"rbd_snap_id\": %lu\n", conn.snap_id);
        fprintf(fp, " },\n");
    }
    fprintf(fp, " \"size\" : %lu\n", conn.info.size);
    fprintf(fp, "}\n");
    clock_gettime(CLOCK_MONOTONIC, &tend);
    fprintf(stderr, "writing of backup job json took about %.5f seconds\n",
            ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
            ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));

    fprintf(stderr, "\nDONE backy backup job json written to: %s\n", arg_new);

    ret = 0;

out:
    backy_rbd_disconnect(&conn);
    g_free();
    exit(ret);
}
