#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <dirent.h>
#include <assert.h>
#include <libgen.h>
#include <stdarg.h>

#define DEBUG_PREFIX "ld_rbd: "

#include "rbd-backy.h"

#define RBD_MAX_FD  255
#define RBD_MAX_DIR  32

#define RBD_LIMIT_NOFILE 16384

#define LD_DLSYM(rsym,sym,name) do { if (!rsym) { rsym = dlsym(RTLD_NEXT, name); if (rsym == NULL) {fprintf(stderr, "Failed to dlsym(%s)", name); exit(10); } } } while (0)

struct rbd_fd_list {
       int fd;
       rados_t cluster;
       rados_ioctx_t io_ctx;
       rbd_image_t image;
       off_t offset;
       uint64_t size;
};

static struct rbd_fd_list rbd_fd_list[RBD_MAX_FD];

static int init_called = 0;

static void ld_rbd_init(void) {
    int i;
    struct rlimit limit;
    if (init_called) return;
    int _errno = errno;
    DPRINTF("ld_rbd_init()");
    for (i = 0; i < RBD_MAX_FD; i++) {
        rbd_fd_list[i].fd = -1;
    }
    if (!getrlimit(RLIMIT_NOFILE, &limit)) {
        DPRINTF("getrlimit RLIMIT_NOFILE soft %lu hard %lu", limit.rlim_cur, limit.rlim_max);
        if (limit.rlim_cur < RBD_LIMIT_NOFILE && limit.rlim_max >= RBD_LIMIT_NOFILE) {
            int ret;
            limit.rlim_cur = RBD_LIMIT_NOFILE;
            errno = 0;
            ret = setrlimit(RLIMIT_NOFILE, &limit);
            if (ret || DEBUG) {
                fprintf(stderr, "ld_rbd: setrlimit RLIMIT_NOFILE soft %lu hard %lu ret %d errno %d\n", limit.rlim_cur, limit.rlim_max, ret, errno);
            }
        }
    }
    init_called = 1;
    errno = _errno;
}

static void ld_rbd_try_fini(void) {
    int i;
    DPRINTF("ld_rbd_try_fini()");
    for (i = 0; i < RBD_MAX_FD; i++) {
        if (rbd_fd_list[i].fd != -1) {
            return;
        }
    }
}

__attribute__((section(".init_array"), used)) static typeof(ld_rbd_init) *init_p = ld_rbd_init;

static struct rbd_fd_list *is_rbd_fd(int fd) {
    int i;
    for (i = 0; i < RBD_MAX_FD; i++) {
        if (rbd_fd_list[i].fd == fd) {
            return &rbd_fd_list[i];
        }
    }
    return NULL;
}

int (*real_open)(__const char *path, int flags, ...);
int open(const char *path, int flags, ...)
{
    LD_DLSYM(real_open, open, "open");
    char *pool = NULL, *namespace = NULL, *imagename = NULL, *snap = NULL;
    rados_t cluster = {0};
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    DPRINTF("open path=%s flags=%d mode=0%o", path, flags, mode);
    if (is_rbd_path(path, &pool, &namespace, &imagename, &snap, &cluster)) {
        int i, fd;
        for (i = 0; i < RBD_MAX_FD; i++) {
            if (rbd_fd_list[i].fd == -1) {
                int r;
                rbd_fd_list[i].cluster = cluster;

                DPRINTF("rados_ioctx_create pool %s", pool);

                r = rados_ioctx_create(cluster, pool, &rbd_fd_list[i].io_ctx);
                if (r < 0) {
                    errno = -r;
                    return -1;
                }

                DPRINTF("rados_ioctx_set_namespace namespace %s", namespace);
                rados_ioctx_set_namespace(rbd_fd_list[i].io_ctx, namespace);   

                if (flags & (O_WRONLY | O_RDWR)) {
                    DPRINTF("rbd_open imagename %s snap %s", imagename, snap);
                    r = rbd_open(rbd_fd_list[i].io_ctx, imagename, &rbd_fd_list[i].image, snap);
                } else {
                    DPRINTF("rbd_open_read_only imagename %s snap %s", imagename, snap);
                    r = rbd_open_read_only(rbd_fd_list[i].io_ctx, imagename, &rbd_fd_list[i].image, snap);
                }
                if (r < 0) {
                    errno = -r;
                    return -1;
                }

                r = rbd_get_size(rbd_fd_list[i].image, &rbd_fd_list[i].size);
                if (r < 0) {
                    errno = -r;
                    return -1;
                }
                DPRINTF("rbd_get_size image %p size %lu", rbd_fd_list[i].image, rbd_fd_list[i].size);

                fd = open("/dev/zero", O_RDONLY);
                assert(fd >= 0);
                DPRINTF("assigning fake fd = %d for rbd image %p", fd, &rbd_fd_list[i].image);
                rbd_fd_list[i].fd = fd;
                rbd_fd_list[i].offset = 0;
                break;
            }
        }
        assert(i < RBD_MAX_FD);
        return fd;
    }
    return real_open(path, flags, mode);
}

int (*real_dup2)(int oldfd, int newfd);
int dup2(int oldfd, int newfd)
{
    LD_DLSYM(real_dup2, dup2, "dup2");
    struct rbd_fd_list *e = is_rbd_fd(oldfd);
    if (e) {
        DPRINTF("dup2 oldfd=%d newfd=%d", oldfd, newfd);
        e->fd = newfd;
    }
    return real_dup2(oldfd, newfd);
}

ssize_t (*real_read)(int fd, void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count) {
    LD_DLSYM(real_read, read, "read");
    struct rbd_fd_list *e = is_rbd_fd(fd);
    if (e) {
        DPRINTF("read fd=%d buf=%p count=%d", fd, buf, (int) count);
        if (e->offset == e->size) {
            return 0;
        }
        int ret = rbd_read(e->image, e->offset, count, buf);
        if (ret < 0) {
            fprintf(stderr, "ld_rbd: read fd=%d buf=%p offset=%ld count=%ld (%s)\n", fd, buf, e->offset, count, strerror(-ret));
            ret = -1;
            errno = -ret;
        }
        if (ret > 0) {
            e->offset += ret;
        }
        return ret;
    }
    return real_read(fd, buf, count);
}

off_t (*real_lseek)(int fd, off_t offset, int whence);
off_t lseek(int fd, off_t offset, int whence) {
    LD_DLSYM(real_lseek, lseek, "lseek");
    DPRINTF("lseek fd=%d offset=%lu whence=%d", fd, offset, whence);
    struct rbd_fd_list *e = is_rbd_fd(fd);
    if (e) {
        off_t new_offset;
        off_t size = e->size;
        switch (whence) {
            case SEEK_SET:
                new_offset = offset;
                break;
            case SEEK_CUR:
                new_offset = e->offset + offset;
                break;
            case SEEK_END:
                new_offset = size + offset;
                break;
            default:
                errno = EINVAL;
                return -1;
        }
        if (new_offset < 0 || new_offset > size) {
            errno = EINVAL;
            return -1;
        }
        e->offset = new_offset;
        return e->offset;
    }
    return real_lseek(fd, offset, whence);
}

ssize_t (*real_write)(int fd, const void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count)
{
    LD_DLSYM(real_write, write, "write");
    struct rbd_fd_list *e = is_rbd_fd(fd);
    if (e) {
        DPRINTF("write fd=%d buf=%p count=%d", fd, buf, (int) count);
        if (e->offset >= e->size) {
            errno = ENOSPC;
            return -1;
        }
        int ret = rbd_write(e->image, e->offset, count, buf);
        if (ret < 0) {
            fprintf(stderr, "ld_rbd: write fd=%d buf=%p offset=%ld count=%ld (%s)\n", fd, buf, e->offset, count, strerror(-ret));
            ret = -1;
            errno = -ret;
        }
        if (ret > 0) {
            e->offset += ret;
            if (e->offset > e->size) e->size = e->offset;
        }
        return ret;
    }
    return real_write(fd, buf, count);
}

ssize_t (*real_pread)(int fd, void *buf, size_t count, off_t offset);
ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    LD_DLSYM(real_pread, pread, "pread");
    struct rbd_fd_list *e = is_rbd_fd(fd);
    if (e) {
        DPRINTF("pread fd=%d buf=%p count=%d off=%ld", fd, buf, (int) count, offset);
        if (offset >= e->size) {
            return 0;
        }
        int ret = rbd_read(e->image, offset, count, buf);
        if (ret < 0) {
            fprintf(stderr, "ld_rbd: pread fd=%d buf=%p offset=%ld count=%ld (%s)\n", fd, buf, offset, count, strerror(-ret));
            errno = -ret;
            return -1;
        }
        return ret;
    }
    return real_read(fd, buf, count);
}

ssize_t (*real_pwrite)(int fd, const void *buf, size_t count, off_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    LD_DLSYM(real_pwrite, pwrite, "pwrite");
    struct rbd_fd_list *e = is_rbd_fd(fd);
    if (e) {
        DPRINTF("pwrite fd=%d buf=%p count=%d off=%ld", fd, buf, (int) count, offset);
        int ret = rbd_write(e->image, offset, count, buf);
        if (ret < 0) {
            fprintf(stderr, "ld_rbd: pwrite fd=%d buf=%p offset=%ld count=%ld (%s)\n", fd, buf, offset, count, strerror(-ret));
            errno = -ret;
            return -1;
        }
        return ret;
    }
    return real_write(fd, buf, count);
}

int (*real_fstat)(int fd, struct stat *buf);
int fstat(int fd, struct stat *buf) {
    LD_DLSYM(real_fstat, fstat, "fstat");
    struct rbd_fd_list *e = is_rbd_fd(fd);
    if (e) {
        DPRINTF("fstat fd=%d", fd);
        errno = ENOTSUP;
        return -1;
    }
    return real_fstat(fd, buf);
}

int (*real_fsync)(int fd) = NULL;
int fsync(int fd) {
    LD_DLSYM(real_fsync, fsync, "fsync");
    DPRINTF("fsync fd=%d", fd);
    struct rbd_fd_list *e = is_rbd_fd(fd);
    if (e) {
        int ret = rbd_flush(e->image);
        if (ret < 0) {
            errno = -ret;
            return -1;
        }
        return 0;
    }
    return real_fsync(fd);
}

int (*real_fdatasync)(int fd) = NULL;
int fdatasync(int fd) {
    LD_DLSYM(real_fdatasync, fdatasync, "fdatasync");
    DPRINTF("fdatasync fd=%d", fd);
    struct rbd_fd_list *e = is_rbd_fd(fd);
    if (e) {
        int ret = rbd_flush(e->image);
        if (ret < 0) {
            errno = -ret;
            return -1;
        }
        return 0;
    }
    return real_fdatasync(fd);
}

int (*real_ftruncate)(int fd, off_t length);
int ftruncate(int fd, off_t length) {
    LD_DLSYM(real_ftruncate, ftruncate, "ftruncate");
    DPRINTF("ftruncate fd=%d length %lu", fd, length);
    struct rbd_fd_list *e = is_rbd_fd(fd);
    if (e) {
        int ret = rbd_resize(e->image, length);
        if (ret < 0) {
            errno = -ret;
            return -1;
        }
        return 0;
    }
    return real_ftruncate(fd, length);
}

int (*real_close)(int fd);
int close(int fd)
{
    LD_DLSYM(real_close, close, "close");
    struct rbd_fd_list *e = is_rbd_fd(fd);
    DPRINTF("close fd=%d", fd);
    if (e) {
        int ret;
        e->fd = -1;
        close(fd);
        if (e->image) {
            DPRINTF("rbd_close %p", &e->image);
            ret = rbd_close(e->image);
            if (ret < 0) {
                errno = -ret;
                return -1;
            }
        }
        if (e->io_ctx) {
            DPRINTF("rbd_ioctx_destroy %p", &e->io_ctx);
            rados_ioctx_destroy(e->io_ctx);
        }
        if (e->cluster) {
            DPRINTF("rados_shutdown()");
            rados_shutdown(e->cluster);
            e->cluster = 0;
        }
        ld_rbd_try_fini();
        return 0;
    }
    return real_close(fd);
}

//~ int (*real_access)(const char *pathname, int mode);
//~ int access(const char *pathname, int mode)
//~ {
    //~ LD_DLSYM(real_access, access, "access");
    //~ DPRINTF("access called %s %d", pathname, mode);
    //~ char *filename;
    //~ if (is_rbd_path(pathname, &filename, 1)) {
        //~ int ret = quobyte_access(filename, mode);
        //~ free(filename);
        //~ ld_rbd_try_fini();
        //~ return ret;
    //~ }
    //~ return real_access(pathname, mode);
//~ }

//~ int (*real_chmod)(const char* path, mode_t mode);
//~ int chmod(const char* path, mode_t mode)
//~ {
    //~ LD_DLSYM(real_chmod, chmod, "chmod");
    //~ DPRINTF("chmod called %s %d", path, mode);
    //~ char *filename;
    //~ if (is_rbd_path(path, &filename, 1)) {
        //~ int ret = quobyte_chmod(filename, mode);
        //~ free(filename);
        //~ ld_rbd_try_fini();
        //~ return ret;
    //~ }
    //~ return real_chmod(path, mode);
//~ }
