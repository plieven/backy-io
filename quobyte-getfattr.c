#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <quobyte.h>
#include <linux/falloc.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char** argv) {
    char *buf = NULL;
    int ret = 1;
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <registry> <path> <attrname>\n", argv[0]);
        exit(1);
    }

    quobyte_create_adapter(argv[1]);

    ret = quobyte_getxattr(argv[2], argv[3], buf, 0);
    if (ret < 0) {
        fprintf(stderr, "quobyte_getxattr %s failed: %s\n", argv[2], strerror(errno));
        goto out;
    }

    buf = malloc(ret);

    ret = quobyte_getxattr(argv[2], argv[3], buf, ret);
    if (ret < 0) {
        fprintf(stderr, "quobyte_getxattr %s failed: %s\n", argv[2], strerror(errno));
        goto out;
    }

    printf("%s", buf);

    ret = 0;
out:
    free(buf);
    quobyte_destroy_adapter();
    
    exit(ret);
}
