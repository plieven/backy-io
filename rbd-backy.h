#include <sys/types.h>
#include <limits.h>

#define OBJ_IS_ALLOCATED(bitmap, i) (bitmap[i / 8] & (1 << (i % 8)))
#define OBJ_SET_ALLOCATED(bitmap, i) (bitmap[i / 8] |= (1 << (i % 8)))
#define OBJ_CLEAR_ALLOCATED(bitmap, i) (bitmap[i / 8] &= ~(1 << (i % 8)))

#include "rbd-parse.h"

#define MAX_SNAPS 100
#define SECURITY_SECS 60

struct rbd_connection {
    rados_t cluster;
    rados_ioctx_t io_ctx;
    rbd_image_t image;
    rbd_image_info_t info;
    char fsid[37];
    char block_name_prefix[RBD_MAX_BLOCK_NAME_SIZE];
    char id[RBD_MAX_BLOCK_NAME_SIZE];
    uint64_t stripe_unit;
    uint64_t stripe_count;
    uint64_t snap_id;
    char *snap_name;
    struct timespec snap_timestamp;
    size_t bitmap_sz;
    char *alloc_bitmap;
    char *change_bitmap;
};

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
    if (r < 0) {
        errno = -r;
        return -1;
    }

    r = rados_cluster_fsid(conn->cluster, &conn->fsid[0], sizeof(conn->fsid));
    assert (r >= 0);

    r = rbd_stat(conn->image, &conn->info, sizeof(conn->info));
    assert(r >= 0);

    conn->bitmap_sz = (conn->info.num_objs + 7) / 8;
    conn->alloc_bitmap = malloc(conn->bitmap_sz);
    assert(conn->alloc_bitmap);
    memset(conn->alloc_bitmap, 0xff, conn->bitmap_sz);
    conn->change_bitmap = malloc(conn->bitmap_sz);
    assert(conn->change_bitmap);
    memset(conn->change_bitmap, 0xff, conn->bitmap_sz);

    r = rbd_get_stripe_unit(conn->image, &conn->stripe_unit);
    assert(r >= 0);

    r = rbd_get_stripe_count(conn->image, &conn->stripe_count);
    assert(r >= 0);

    r = rbd_get_block_name_prefix(conn->image, &conn->block_name_prefix[0], sizeof(conn->block_name_prefix));
    assert(r >= 0);

    r = rbd_get_id(conn->image, &conn->id[0], sizeof(conn->id));
    assert(r >= 0);

    if (snap) {
        //TODO: from octopus on we can use rbd_snap_get_id here
        int max_snaps = MAX_SNAPS, i;
        rbd_snap_info_t  snaps[MAX_SNAPS];
        r = rbd_snap_list(conn->image, &snaps[0], &max_snaps);
        assert(r >= 0);
        assert(max_snaps == MAX_SNAPS);
        for (i = 0; i < max_snaps; i++) {
            if (snaps[i].id && !strcmp(snap, snaps[i].name)) {
                assert(!conn->snap_id);
                conn->snap_id = snaps[i].id;
                conn->snap_name = strdup(snap);
            }
        }
        assert(conn->snap_id);
        r = rbd_snap_get_timestamp(conn->image, conn->snap_id, &conn->snap_timestamp);
        assert(r >= 0);
    }

    fprintf(stderr, "size %lu obj_size %lu num_objs %lu stripe_unit %lu stripe_count %lu snap_id %lu prefix %s\n", conn->info.size, conn->info.obj_size, conn->info.num_objs, conn->stripe_unit, conn->stripe_count, conn->snap_id, conn->block_name_prefix);
    return 0;
}

static void backy_rbd_disconnect(struct rbd_connection *conn) {
    free(conn->alloc_bitmap);
    free(conn->change_bitmap);
    if (conn->image) {
        rbd_close(conn->image);
    }
    if (conn->io_ctx) {
        rados_ioctx_destroy(conn->io_ctx);
    }
    if (conn->cluster) {
        rados_shutdown(conn->cluster);
    }
    free(conn->snap_name);
    memset(conn, 0x0, sizeof(struct rbd_connection));
}

static int backy_rbd_diff_cb(uint64_t offs, size_t len, int exists, void* opaque) {
    struct rbd_connection *conn = opaque;
    assert(!(offs % conn->info.obj_size));
    assert(len <= conn->info.obj_size);
    if (exists) {
        OBJ_SET_ALLOCATED(conn->alloc_bitmap, offs / conn->info.obj_size);
        OBJ_SET_ALLOCATED(conn->change_bitmap, offs / conn->info.obj_size);
    } else {
        assert(!OBJ_IS_ALLOCATED(conn->alloc_bitmap, offs / conn->info.obj_size));
        assert(!OBJ_IS_ALLOCATED(conn->change_bitmap, offs / conn->info.obj_size));
    }
    return 0;
}

static long backy_rbd_changed_objs(struct rbd_connection *conn, time_t since) {
    struct timespec tstart={}, tend={};
    long ret = -1;
    unsigned int i;
    int r;

    if (since) {
        if (conn->stripe_unit != conn->info.obj_size || conn->stripe_count != 1) {
            errno = EINVAL;
            return -1;
        }
    }

    memset(conn->alloc_bitmap, 0x00, conn->bitmap_sz);
    memset(conn->change_bitmap, 0x00, conn->bitmap_sz);

    /* fill bitmap with allocated clusters */
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    r = rbd_diff_iterate2(conn->image, NULL, 0, conn->info.size, true, true, backy_rbd_diff_cb, conn);
    clock_gettime(CLOCK_MONOTONIC, &tend);
    fprintf(stderr, "backy_rbd_changed_objs (rbd_diff_iterate2) took about %.5f seconds\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
    assert(r >= 0);

    if (since) {
        assert(conn->info.num_objs <= UINT_MAX);
        clock_gettime(CLOCK_MONOTONIC, &tstart);

        if (conn->snap_id) {
            rados_ioctx_snap_set_read(conn->io_ctx, conn->snap_id);
        }
        for (i = 0; i < conn->info.num_objs; i++) {   
            char obj_name[RBD_MAX_BLOCK_NAME_SIZE + 16 + 1 + 1];
            uint64_t size;
            time_t pmtime;
            if (!OBJ_IS_ALLOCATED(conn->change_bitmap, i)) continue;
            snprintf(obj_name, sizeof(obj_name) - 1, "%s.%016x", conn->block_name_prefix, i);
            r = rados_stat(conn->io_ctx, obj_name, &size, &pmtime);
            if (r < 0) {
                fprintf(stderr, "rados_stat object %u (%s) failed with (%s)\n", i, obj_name, strerror(-r));
            }
            assert(r >= 0);
            if (pmtime + SECURITY_SECS < since) {
                OBJ_CLEAR_ALLOCATED(conn->change_bitmap, i);
            }
        }
        if (conn->snap_id) {
            rados_ioctx_snap_set_read(conn->io_ctx, LIBRADOS_SNAP_HEAD);
        }
        clock_gettime(CLOCK_MONOTONIC, &tend);
        fprintf(stderr, "backy_rbd_changed_objs (rados_stat since %ld) took about %.5f seconds\n", since,
               ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
               ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
        fflush(stderr);
    }

    ret = 0;
    for (i = 0; i < conn->info.num_objs; i++) {
        if (OBJ_IS_ALLOCATED(conn->change_bitmap, i)) {
            ret++;
        }
    }

    return ret;
}

static long backy_rbd_changed_objs_from_snap(struct rbd_connection *conn, char *old_snap_name) {
    struct timespec tstart={}, tend={};
    long ret = -1;
    unsigned int i;
    int r;

    memset(conn->alloc_bitmap, 0x00, conn->bitmap_sz);
    memset(conn->change_bitmap, 0x00, conn->bitmap_sz);

    /* fill bitmap with allocated clusters */
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    r = rbd_diff_iterate2(conn->image, NULL, 0, conn->info.size, true, true, backy_rbd_diff_cb, conn);
    clock_gettime(CLOCK_MONOTONIC, &tend);
    fprintf(stderr, "backy_rbd_changed_objs_from_snap (rbd_diff_iterate2) took about %.5f seconds\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
    assert(r >= 0);

    /* fill bitmap with changed clusters */
    memset(conn->change_bitmap, 0x00, conn->bitmap_sz);
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    r = rbd_diff_iterate2(conn->image, old_snap_name, 0, conn->info.size, true, true, backy_rbd_diff_cb, conn);
    clock_gettime(CLOCK_MONOTONIC, &tend);
    fprintf(stderr, "backy_rbd_changed_objs_from_snap (rbd_diff_iterate2 from snap %s) took about %.5f seconds\n", old_snap_name,
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
    assert(r >= 0);

    ret = 0;
    for (i = 0; i < conn->info.num_objs; i++) {
        if (OBJ_IS_ALLOCATED(conn->change_bitmap, i)) {
            ret++;
        }
    }

    return ret;
}

//TODO: from octopus on we can use builtin rbd_snap_exists here
static int rbd_snap_exists(rbd_image_t image, const char *snapname, bool *exists) {
    int max_snaps = MAX_SNAPS, i;
    rbd_snap_info_t  snaps[MAX_SNAPS];

    *exists = false;
    int r = rbd_snap_list(image, &snaps[0], &max_snaps);
    if (r < 0) {
        return r;
    }
    assert(max_snaps == MAX_SNAPS);
    for (i = 0; i < max_snaps; i++) {
        if (snaps[i].id && !strcmp(snapname, snaps[i].name)) {
            *exists = true;
        }
    }
}

static int rbd_parse_json(struct rbd_connection *conn, char *path, time_t *snap_timestamp, char **snap_name) {
	int i, ret = 1;
	struct timespec tstart={}, tend={};
	json_value* value = NULL;

	int fd = open(path, O_RDONLY, 0);
	if (fd < 0) {
		fprintf(stderr, "fopen %s failed: %s\n", path, strerror(errno));
		goto out;
	}
	clock_gettime(CLOCK_MONOTONIC, &tstart);
	if (parse_json(fd)) {
	   fprintf(stderr, "cant json parse: %s\n", path);
	   goto out;
	}
	clock_gettime(CLOCK_MONOTONIC, &tend);
	fprintf(stderr, "parse_json took about %.5f seconds\n",
		   ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
		   ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec));
	fflush(stderr);
	close(fd);

    if (g_version < 2) {
        fprintf(stderr, "backy version is < 2\n");
        goto out;
    }
    if (!g_metadata) {
        fprintf(stderr, "json has no metadata section\n");
        goto out;
    }

	value = json_parse((json_char*) g_metadata, strlen(g_metadata));

	if (!value || value->type != json_object) {
		fprintf(stderr, "json metadata parse error\n");
		goto out;
	}

	for (i = 0; i < value->u.object.length; i++) {
		json_char *name = value->u.object.values[i].name;
		json_value *val = value->u.object.values[i].value;
		if (!strcmp(name, "rbd_id")) {
			vgotoout_if_n(val->type != json_string, "json parser error: rbd_id has unexpected type (%d)", val->type);
			vgotoout_if_n(val->u.string.length != strlen(&conn->id[0]) || strncmp(&conn->id[0], val->u.string.ptr, strlen(&conn->id[0])), "rbd_id in metadata does not match!", 0);
		} else if (!strcmp(name, "rados_cluster_fsid")) {
			vgotoout_if_n(val->type != json_string, "json parser error: rados_cluster_fsid has unexpected type (%d)", val->type);
			vgotoout_if_n(val->u.string.length != strlen(&conn->fsid[0]) || strncmp(&conn->fsid[0], val->u.string.ptr, strlen(&conn->fsid[0])), "rados_cluster_fsid in metadata does not match!", 0);
		} else if (!strcmp(name, "rbd_snap_timestamp")) {
			vgotoout_if_n(val->type != json_integer, "json parser error: rbd_snap_timestamp has unexpected type (%d)", val->type);
            *snap_timestamp = val->u.integer;
        } else if (!strcmp(name, "rbd_snap_name")) {
            bool snap_exists;
            vgotoout_if_n(val->type != json_string, "json parser error: rbd_snap_name has unexpected type (%d)", val->type);
            if (snap_name) {
                /* check if snapshot still exists */
                int r = rbd_snap_exists(conn->image, val->u.string.ptr, &snap_exists);
                assert(r >= 0);
                if (snap_exists) {
                    fprintf(stderr, "parse_json rbd_snap_name '%s' sill exists on cluster!\n", val->u.string.ptr);
                    *snap_name = strdup(val->u.string.ptr);
                }
            }
        } else {
            fprintf(stderr, "cannot handle metadata: %s\n", name);
        }
	}

	assert(g_block_size == conn->info.obj_size);

	ret = 0;
out:
	return ret;
}
