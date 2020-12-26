#include <rbd/librbd.h>

#ifdef DEBUG
#define DPRINTF(fmt,args...) do { fprintf(stderr, DEBUG_PREFIX);fprintf(stderr, (fmt), ##args); fprintf(stderr,"\n"); } while (0);
#else
#define DPRINTF(fmt,args...)
#define DEBUG 0
#endif

static int is_rbd_path(const char *path, char **pool, char **namespace, char **imagename, char **snap, rados_t *cluster) {
    char *tmp, *opts;
    char* id = "admin";
    char* conf = "/etc/ceph/ceph.conf";
    int r = 0;

    *pool = NULL;
    *namespace = NULL;
    *imagename = NULL;
    *snap = NULL;
    *cluster = 0;

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

