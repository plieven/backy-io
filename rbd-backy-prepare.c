#include "backy.h"

#define DEBUG_PREFIX "rbd-backy-prepare"

#include "rbd-backy.h"

int main(int argc, char** argv) {
    int ret = 1;
    long r, i, num_changed = 0;
    struct rbd_connection conn = {0};

    /* config, should be passed via cli */
    const char *rbd_path = "rbd:dhp-high-performance/c4ca7ee9-36ce-4fc9-9d3b-ece8a4f8b83e/bb262b5c-9dfc-457a-86cb-18113cee4cfe.raw@snaptest:id=dlp:conf=/etc/ceph/ceph-dev01.conf";
    time_t since = time(NULL) - 21*86400;

    r = backy_rbd_connect(rbd_path, &conn);
    assert (!r);

    r = backy_rbd_changed_objs(&conn, since, 0);
    assert (r>=0);

    fprintf(stderr, "number of changed objects = %ld\n", r);

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

    backy_rbd_disconnect(&conn);
    g_free();
    exit(ret);
}
