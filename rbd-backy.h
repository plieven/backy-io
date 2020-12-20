#include <rbd/librbd.h>

#define OBJ_IS_ALLOCATED(bitmap, i) (bitmap[i / 8] & (1 << (i % 8)))
#define OBJ_SET_ALLOCATED(bitmap, i) (bitmap[i / 8] |= (1 << (i % 8)))
#define OBJ_CLEAR_ALLOCATED(bitmap, i) (bitmap[i / 8] &= ~(1 << (i % 8)))

#ifdef DEBUG
#define DPRINTF(fmt,args...) do { fprintf(stderr, DEBUG_PREFIX);fprintf(stderr, (fmt), ##args); fprintf(stderr,"\n"); } while (0);
#else
#define DPRINTF(fmt,args...)
#define DEBUG 0
#endif

#define MAX_SNAPS 100
#define SECURITY_SECS 300

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

static int is_rbd_path(const char *path, char **pool, char **namespace, char **imagename, char **snap, rados_t *cluster) {
    char *tmp, *opts;
    char* id = "admin";
    char* conf = "/etc/ceph/ceph.conf";
    int r = 0;
    if (strncmp(path, "rbd:", 4)) {
        return 0;
    }

    *pool = strdup(path + 4);
    opts = strchr(*pool, ':');
    if (opts) {
        char *k, *v;
        *opts = 0;
        opts++;
        
        do {
            k = opts;
            opts = strchr(opts, ':');
            if (opts) {
                *opts = 0;
                opts++;
            }
            tmp = strchr(k, '=');
            if (tmp) {
                *tmp = 0;
                v = tmp + 1;
                if (!strcmp(k, "id")) {
                    id = v;
                } else if (!strcmp(k, "conf")) {
                    conf = v;
                } else {
                    fprintf(stderr, DEBUG_PREFIX "ignoring unknown config key: %s\n", k);
                }
            }
        } while (opts);
    }

    tmp = strchr(*pool, '/');
    if (!tmp) {
        goto out;
    }
    *imagename = strdup(tmp + 1);
    *tmp = 0;

    tmp = strchr(*imagename, '/');
    if (tmp) {
        *namespace = *imagename;
        *imagename = strdup(tmp + 1);
        *tmp = 0;
    }

    tmp = strchr(*imagename, '@');
    if (tmp) {
        *snap = strdup(tmp + 1);
        *tmp = 0;
    }

    DPRINTF("connecting to rados cluster with id=%s conf=%s...", id, conf);

    r = rados_create(cluster, id);
    assert (r >= 0);

    r = rados_conf_read_file(*cluster, conf);
    if (r < 0) {
        fprintf(stderr, DEBUG_PREFIX "rados_conf_read failed (%s)\n", strerror(-r));
        r = 0;
        goto out;
    }

    r = rados_connect(*cluster);
    if (r < 0) {
        fprintf(stderr, "rados_connnect failed (%s)\n", strerror(-r));
        r = 0;
        goto out;
    }

    assert(r >= 0);

    DPRINTF("is_rbd_path pool %s namespace %s imagename %s snap %s", *pool, *namespace, *imagename, *snap);
    r = 1;

out:
    if (!r) {
        free(*pool);
        free(*namespace);
        free(*imagename);
        free(*snap);
        if (*cluster) {
            rados_shutdown(*cluster);
            *cluster = 0;
        }
    }
    return r;
}

static int backy_rbd_connect(const char *path, struct rbd_connection *conn) {
    char *image_name;
    char *pool;
    char *snap;
    char *namespace;
    int r;

    r = is_rbd_path(path, &pool, &namespace, &image_name, &snap, &conn->cluster);
    if (!r) {
        errno = EINVAL;
        return -1;
    }

    r = rados_ioctx_create(conn->cluster, pool, &conn->io_ctx);
    assert(r >= 0);

    rados_ioctx_set_namespace(conn->io_ctx, namespace);    

    r = rbd_open_read_only(conn->io_ctx, image_name, &conn->image, snap);
    assert(r >= 0);

    r = rbd_stat(conn->image, &conn->info, sizeof(conn->info));
    assert(r >= 0);

    conn->bitmap_sz = (conn->info.num_objs + 7) / 8;
    free(conn->bitmap);
    conn->bitmap = calloc(1, conn->bitmap_sz);
    assert(conn->bitmap);

    r = rbd_get_stripe_unit(conn->image, &conn->stripe_unit);
    assert(r >= 0);

    r = rbd_get_stripe_count(conn->image, &conn->stripe_count);
    assert(r >= 0);

    r = rbd_get_block_name_prefix(conn->image, &conn->block_name_prefix[0], sizeof(conn->block_name_prefix));
    assert(r >= 0);

    if (snap) {
        int max_snaps = MAX_SNAPS, i;
        rbd_snap_info_t  snaps[MAX_SNAPS];
        r = rbd_snap_list(conn->image, &snaps[0], &max_snaps);
        assert(r >= 0);
        assert(max_snaps == MAX_SNAPS);
        for (i = 0; i < max_snaps; i++) {
            if (snaps[i].id && !strcmp(snap, snaps[i].name)) {
                assert(!conn->snap_id);
                conn->snap_id = snaps[i].id;
            }
        }
        assert(conn->snap_id);
    }

    fprintf(stderr, "size %lu obj_size %lu num_objs %lu stripe_unit %lu stripe_count %lu snap_id %lu prefix %s\n", conn->info.size, conn->info.obj_size, conn->info.num_objs, conn->stripe_unit, conn->stripe_count, conn->snap_id, conn->block_name_prefix);
    return 0;
}

static int backy_rbd_disconnect(struct rbd_connection *conn) {
    free(conn->bitmap);
    if (conn->image) {
        rbd_close(conn->image);
    }
    if (conn->io_ctx) {
        rados_ioctx_destroy(conn->io_ctx);
    }
    if (conn->cluster) {
        rados_shutdown(conn->cluster);
    }
    memset(conn, 0x0, sizeof(struct rbd_connection));
}

static int backy_rbd_diff_cb(uint64_t offs, size_t len, int exists, void* opaque) {
    struct rbd_connection *conn = opaque;
    assert(!(offs % conn->info.obj_size));
    assert(len == conn->info.obj_size);
    OBJ_SET_ALLOCATED(conn->bitmap, offs / conn->info.obj_size);
    return 0;
}

static long backy_rbd_changed_objs(struct rbd_connection *conn, time_t since, int recovery) {
    long ret = -1;
    unsigned int i;
    int r;

    if (since) {
        if (conn->stripe_unit != conn->info.obj_size || conn->stripe_count != 1) {
            errno = EINVAL;
            return -1;
        }
    }

    /* fill bitmap with allocated clusters */
    r = rbd_diff_iterate2(conn->image, NULL, 0, conn->info.size, true, true, backy_rbd_diff_cb, conn);
    assert(r >= 0);

    if (since) {
        assert(conn->info.num_objs <= UINT_MAX);
        if (conn->snap_id) {
            rados_ioctx_snap_set_read(conn->io_ctx, conn->snap_id);
        }
        for (i = 0; i < conn->info.num_objs; i++) {   
            char obj_name[RBD_MAX_BLOCK_NAME_SIZE + 16 + 1 + 1];
            uint64_t size;
            time_t pmtime;
            if (!OBJ_IS_ALLOCATED(conn->bitmap, i)) continue;
            snprintf(obj_name, sizeof(obj_name) - 1, "%s.%016x", conn->block_name_prefix, i);
            r = rados_stat(conn->io_ctx, obj_name, &size, &pmtime);
            /* fprintf(stderr, "%s size %lu pmtime %lu\n", obj_name, size, pmtime); */
            assert(r >= 0);
            if (pmtime + SECURITY_SECS < since) {
                OBJ_CLEAR_ALLOCATED(conn->bitmap, i);
            }
        }
        if (conn->snap_id) {
            rados_ioctx_snap_set_read(conn->io_ctx, LIBRADOS_SNAP_HEAD);
        }
    }

    ret = 0;
    for (i = 0; i < conn->info.num_objs; i++) {
        if (OBJ_IS_ALLOCATED(conn->bitmap, i)) {
            ret++;
        }
    }
    
    return ret;
}
