#include "backy.h"
#include <rbd/librbd.h>

#define OBJ_IS_ALLOCATED(bitmap, i) (bitmap[i / 8] & (1 << (i % 8)))
#define OBJ_SET_ALLOCATED(bitmap, i) (bitmap[i / 8] |= (1 << (i % 8)))
#define OBJ_CLEAR_ALLOCATED(bitmap, i) (bitmap[i / 8] &= ~(1 << (i % 8)))

#define MAX_SNAPS 100
#define SECURITY_SECS 600

struct rbd_connection {
    rados_t cluster;
    rados_ioctx_t io_ctx;
    rbd_image_t image;
    rbd_image_info_t info;
    char block_name_prefix[RBD_MAX_BLOCK_NAME_SIZE];
    uint64_t stripe_unit;
    uint64_t stripe_count;
    uint64_t snap_id;
    size_t bitmap_sz;
    char *bitmap;
};

int diff_cb(uint64_t offs, size_t len, int exists, void* opaque) {
    struct rbd_connection *conn = opaque;
    assert(!(offs % conn->info.obj_size));
    assert(len == conn->info.obj_size);
    OBJ_SET_ALLOCATED(conn->bitmap, offs / conn->info.obj_size);
    return 0;
}


int main(int argc, char** argv) {
    int ret = 1, r;
    long i, num_changed = 0;
    struct rbd_connection conn = {0};

    /* config, should be passed via cli */
    char *conf = "/etc/ceph/ceph-dev01.conf";
    char *id = "dlp";
    char *image_name = "bb262b5c-9dfc-457a-86cb-18113cee4cfe.raw";
    char *pool = "dhp-high-performance";
    char *snap = "snaptest";
    char *namespace = "c4ca7ee9-36ce-4fc9-9d3b-ece8a4f8b83e";
    time_t since = time(NULL) - 3 * 86400;

    r = rados_create(&conn.cluster, id);
    assert (r >= 0);
    
    r = rados_conf_read_file(conn.cluster, conf);
    assert (r >= 0);
    
    r = rados_connect(conn.cluster);
    assert(r >= 0);

    r = rados_ioctx_create(conn.cluster, pool, &conn.io_ctx);
    assert(r >= 0);

    rados_ioctx_set_namespace(conn.io_ctx, namespace);    

    r = rbd_open_read_only(conn.io_ctx, image_name, &conn.image, snap);
    assert(r >= 0);

    r = rbd_stat(conn.image, &conn.info, sizeof(conn.info));
    assert(r >= 0);

    conn.bitmap_sz = (conn.info.num_objs + 7) / 8;
    free(conn.bitmap);
    conn.bitmap = calloc(1, conn.bitmap_sz);
    assert(conn.bitmap);

    r = rbd_get_stripe_unit(conn.image, &conn.stripe_unit);
    assert(r >= 0);

    r = rbd_get_stripe_count(conn.image, &conn.stripe_count);
    assert(r >= 0);

    r = rbd_get_block_name_prefix(conn.image, &conn.block_name_prefix, sizeof(conn.block_name_prefix));
    assert(r >= 0);

    if (snap) {
        int max_snaps = MAX_SNAPS;
        rbd_snap_info_t  snaps[MAX_SNAPS];
        r = rbd_snap_list(conn.image, &snaps, &max_snaps);
        assert(r >= 0);
        assert(max_snaps == MAX_SNAPS);
        for (i = 0; i < max_snaps; i++) {
            if (snaps[i].id && !strcmp(snap, snaps[i].name)) {
                assert(!conn.snap_id);
                conn.snap_id = snaps[i].id;
            }
        }
        assert(conn.snap_id);
    }

    fprintf(stderr, "size %lu obj_size %lu num_objs %lu stripe_unit %lu stripe_count %lu snap_id %lu prefix %s\n", conn.info.size, conn.info.obj_size, conn.info.num_objs, conn.stripe_unit, conn.stripe_count, conn.snap_id, conn.block_name_prefix);
    if (since) {
        assert(conn.stripe_unit == conn.info.obj_size);
        assert(conn.stripe_count == 1);
    }

    /* fill bitmap with allocated clusters */
    r = rbd_diff_iterate2(conn.image, NULL, 0, conn.info.size, true, true, diff_cb, &conn);
    assert(r >= 0);

    if (since) {
        if (conn.snap_id) {
            rados_ioctx_snap_set_read(conn.io_ctx, conn.snap_id);
        }
        for (i = 0; i < conn.info.num_objs; i++) {   
            char obj_name[RBD_MAX_BLOCK_NAME_SIZE + 16 + 1 + 1];
            uint64_t size;
            time_t pmtime;
            if (!OBJ_IS_ALLOCATED(conn.bitmap, i)) continue;
            snprintf(obj_name, sizeof(obj_name) - 1, "%s.%016x", conn.block_name_prefix, i);
            r = rados_stat(conn.io_ctx, obj_name, &size, &pmtime);
            /* fprintf(stderr, "%s size %lu pmtime %lu\n", obj_name, size, pmtime); */
            assert(r >= 0);
            if (pmtime + SECURITY_SECS < since) {
                OBJ_CLEAR_ALLOCATED(conn.bitmap, i);
            }
        }
        if (conn.snap_id) {
            rados_ioctx_snap_set_read(conn.io_ctx, LIBRADOS_SNAP_HEAD);
        }
    }

    for (i = 0; i < conn.info.num_objs; i++) {
        if (!(i % 64)) fprintf(stderr, "\n");
        if (OBJ_IS_ALLOCATED(conn.bitmap, i)) {
            num_changed++;
            fprintf(stderr, "X");
        } else {
            fprintf(stderr, ".");
        }
    }
    fprintf(stderr, "\n\n");
    fprintf(stderr, "number of changed objects = %ld\n", num_changed);

    ret = 0;
out:
    free(conn.bitmap);
    if (conn.image) {
        rbd_close(conn.image);
    }
    if (conn.io_ctx) {
        rados_ioctx_destroy(conn.io_ctx);
    }
    if (conn.cluster) {
        rados_shutdown(conn.cluster);
    }
    g_free();
    exit(ret);
}
