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
#include <quobyte.h>

#define QUOBYTE_MAX_FD  255
#define QUOBYTE_MAX_DIR  32

#define QUOBYTE_LIMIT_NOFILE 16384

#ifdef DEBUG
#define LD_QUOBYTE_DPRINTF(fmt,args...) do { fprintf(stderr,"ld_quobyte: ");fprintf(stderr, (fmt), ##args); fprintf(stderr,"\n"); } while (0);
#else
#define LD_QUOBYTE_DPRINTF(fmt,args...)
#define DEBUG 0
#endif

#define LD_DLSYM(rsym,sym,name) do { if (!rsym) { rsym = dlsym(RTLD_NEXT, name); if (rsym == NULL) {fprintf(stderr, "Failed to dlsym(%s)", name); exit(10); } } } while (0)

struct quobyte_fd_list {
       int fd;
       struct quobyte_fh* fh;
       off_t offset;
       off_t size;
};

struct quobyte_dir_list {
       DIR *dirp;
};

static struct quobyte_fd_list quobyte_fd_list[QUOBYTE_MAX_FD];
static struct quobyte_dir_list quobyte_dir_list[QUOBYTE_MAX_DIR];

static int init_called = 0;
static char *qRegistry = NULL;

static void ld_quobyte_init(void) {
    int i;
    struct rlimit limit;
    if (init_called) return;
    int _errno = errno;
    LD_QUOBYTE_DPRINTF("ld_quobyte_init()");
    for (i = 0; i < QUOBYTE_MAX_FD; i++) {
        quobyte_fd_list[i].fd = -1;
    }
    for (i = 0; i < QUOBYTE_MAX_DIR; i++) {
        quobyte_dir_list[i].dirp = NULL;
    }
    if (!getrlimit(RLIMIT_NOFILE, &limit)) {
        LD_QUOBYTE_DPRINTF("getrlimit RLIMIT_NOFILE soft %lu hard %lu", limit.rlim_cur, limit.rlim_max);
        if (limit.rlim_cur < QUOBYTE_LIMIT_NOFILE && limit.rlim_max >= QUOBYTE_LIMIT_NOFILE) {
            int ret;
            limit.rlim_cur = QUOBYTE_LIMIT_NOFILE;
            errno = 0;
            ret = setrlimit(RLIMIT_NOFILE, &limit);
            if (ret || DEBUG) {
                fprintf(stderr, "ld_quobyte: setrlimit RLIMIT_NOFILE soft %lu hard %lu ret %d errno %d\n", limit.rlim_cur, limit.rlim_max, ret, errno);
            }
        }
    }
    init_called = 1;
    errno = _errno;
}

static void ld_quobyte_try_fini(void) {
    int i;
    LD_QUOBYTE_DPRINTF("ld_quobyte_try_fini()");
    for (i = 0; i < QUOBYTE_MAX_FD; i++) {
        if (quobyte_fd_list[i].fd != -1) {
            return;
        }
    }
    for (i = 0; i < QUOBYTE_MAX_DIR; i++) {
        if (quobyte_dir_list[i].dirp != NULL) {
            return;
        }
    }
    if (qRegistry) {
        int _errno = errno;
        LD_QUOBYTE_DPRINTF("quobyte_destroy_adapter()");
        quobyte_destroy_adapter();
        free(qRegistry);
        qRegistry = NULL;
        errno = _errno;
    }
}

__attribute__((section(".init_array"), used)) static typeof(ld_quobyte_init) *init_p = ld_quobyte_init;

static int is_quobyte_path(const char *path, char **filename, int follow_symlink) {
    char *registry, *tmp;
    int ret = 0;
    if (strncmp(path, "quobyte://", 10) && strncmp(path, "quobyte:\\\\", 10)) {
        return 0;
    }
    registry = strdup(path + 10);
    tmp = strchr(registry, '/');
    if (!tmp) {
        goto out;
    }
    *filename = strdup(tmp);
    *tmp = 0;
    if (!qRegistry) {
        LD_QUOBYTE_DPRINTF("connecting to registry %s", registry);
        if (quobyte_create_adapter(registry)) {
            goto out;
        }
        qRegistry = strdup(registry);
    }
    ret = 1;
    if (follow_symlink) {
        char link[PATH_MAX];
        int ret2 = quobyte_readlink(*filename, &link[0], PATH_MAX);
        if (!ret2) {
            if (link[0] == '/') {
                free(*filename);
                *filename = strdup(&link[0]);
            } else {
                char rellink[PATH_MAX];
                snprintf(&rellink[0], PATH_MAX, "%s/%s", dirname(*filename), &link[0]);
                free(*filename);
                *filename = strdup(&rellink[0]);
            }
        }
    }
out:
    free(registry);
    return ret;
}

static struct quobyte_fd_list *is_quobyte_fd(int fd) {
    int i;
    for (i = 0; i < QUOBYTE_MAX_FD; i++) {
        if (quobyte_fd_list[i].fd == fd) {
            return &quobyte_fd_list[i];
        }
    }
    return NULL;
}

static int is_quobyte_dh(DIR *dirp) {
    int i;
    for (i = 0; i < QUOBYTE_MAX_DIR; i++) {
        if (quobyte_dir_list[i].dirp == dirp) {
            return 1;
        }
    }
    return 0;
}

DIR *(*real_opendir)(const char *name) = NULL;
DIR *opendir(const char *name) {
    char *filename;
    DIR* ret;
    ld_quobyte_init();
    LD_DLSYM(real_opendir, opendir, "opendir");
    LD_QUOBYTE_DPRINTF("opendir name=%s", name);
    if (is_quobyte_path(name, &filename, 0)) {
        int i;
        DIR *dh = (DIR*) quobyte_opendir(filename);
        free(filename);
        if (!dh) {
            LD_QUOBYTE_DPRINTF("opendir ret=%p", NULL);
            ld_quobyte_try_fini();
            return NULL;
        }
        for (i = 0; i < QUOBYTE_MAX_DIR; i++) {
            if (!quobyte_dir_list[i].dirp) {
                quobyte_dir_list[i].dirp = dh;
                break;
            }
        }
        assert(i < QUOBYTE_MAX_DIR);
        LD_QUOBYTE_DPRINTF("opendir ret=%p", dh);
        return dh;
    }
    ret = real_opendir(name);
    LD_QUOBYTE_DPRINTF("opendir ret=%p", ret);
    return ret;
}

long (*real_telldir)(DIR *dirp) = NULL;
long telldir(DIR *dirp) {
    LD_DLSYM(real_telldir, telldir, "telldir");
    LD_QUOBYTE_DPRINTF("telldir dirp=%p", dirp);
    if (is_quobyte_dh(dirp)) {
        return quobyte_telldir((struct quobyte_dh*) dirp);
    }
    return real_telldir(dirp);
}

void (*real_seekdir)(DIR *dirp, long loc) = NULL;
void seekdir(DIR *dirp, long loc) {
    LD_DLSYM(real_seekdir, seekdir, "seekdir");
    LD_QUOBYTE_DPRINTF("seekdir dirp=%p loc=%ld", dirp, loc);
    if (is_quobyte_dh(dirp)) {
        return quobyte_seekdir((struct quobyte_dh*) dirp, loc);
    }
    real_seekdir(dirp, loc);
}

struct dirent *(*real_readdir)(DIR *dirp) = NULL;
struct dirent *readdir(DIR *dirp) {
    LD_DLSYM(real_readdir, readdir, "readdir");
    LD_QUOBYTE_DPRINTF("readdir dirp=%p", dirp);
    if (is_quobyte_dh(dirp)) {
        return quobyte_readdir((struct quobyte_dh*) dirp);
    }
    return real_readdir(dirp);
}

int (*real_closedir)(DIR *dirp) = NULL;
int closedir(DIR *dirp) {
    LD_DLSYM(real_closedir, closedir, "closedir");
    LD_QUOBYTE_DPRINTF("closedir dirp=%p", dirp);
    if (is_quobyte_dh(dirp)) {
        int i;
        int ret = quobyte_closedir((struct quobyte_dh*) dirp);
        for (i = 0; i < QUOBYTE_MAX_DIR; i++) {
            if (quobyte_dir_list[i].dirp == dirp) {
                quobyte_dir_list[i].dirp = NULL;
            }
        }
        ld_quobyte_try_fini();
        return ret;
    }
    return real_closedir(dirp);
}

int (*real_xstat)(int ver, const char *path, struct stat *buf) = NULL;
int __xstat(int ver, const char *path, struct stat *buf) {
    LD_DLSYM(real_xstat, __xstat, "__xstat");
    LD_QUOBYTE_DPRINTF("__xstat ver=%d path=%s buf=%p", ver, path, buf);
    char *filename;
    if (is_quobyte_path(path, &filename, 1)) {
        int ret = quobyte_getattr(filename, buf);
        free(filename);
        ld_quobyte_try_fini();
        return ret;
    }
    return real_xstat(ver, path, buf);
}

int (*real_fxstat)(int ver, int fd, struct stat *buf) = NULL;
int __fxstat(int ver, int fd, struct stat *buf) {
    LD_DLSYM(real_fxstat, __fxstat, "__fxstat");
    LD_QUOBYTE_DPRINTF("__fxstat ver=%d fd=%d buf=%p", ver, fd, buf);
    struct quobyte_fd_list *e = is_quobyte_fd(fd);
    if (e) {
        return quobyte_fstat(e->fh, buf);
    }
    return real_fxstat(ver, fd, buf);
}

int (*real_lxstat)(int ver, const char *path, struct stat *buf) = NULL;
int __lxstat(int ver, const char *path, struct stat *buf) {
    LD_DLSYM(real_lxstat, __lstat, "__lxstat");
    LD_QUOBYTE_DPRINTF("__lxstat ver=%d path=%s buf=%p", ver, path, buf);
    char *filename;
    if (is_quobyte_path(path, &filename, 0)) {
        int ret = quobyte_getattr(filename, buf);
        free(filename);
        ld_quobyte_try_fini();
        return ret;
    }
    return real_lxstat(ver, path, buf);
}

ssize_t (*real_readlink)(const char *path, char *buf, size_t bufsiz) = NULL;
ssize_t readlink(const char *path, char *buf, size_t bufsiz) {
    char *filename;
    LD_DLSYM(real_readlink, readlink, "readlink");
    LD_QUOBYTE_DPRINTF("readlink path=%s buf=%p bufsiz=%d", path, buf, (int) bufsiz);
    if (is_quobyte_path(path, &filename, 0)) {
        int ret = quobyte_readlink(filename, buf, bufsiz);
        free(filename);
        ld_quobyte_try_fini();
        return ret;
    }
    return real_readlink(path, buf, bufsiz);
}

ssize_t (*real_getxattr)(const char *path, const char *name, void *value, size_t size) = NULL;
ssize_t getxattr(const char *path, const char *name, void *value, size_t size) {
    LD_DLSYM(real_getxattr, getxattr, "getxattr");
    LD_QUOBYTE_DPRINTF("getxattr called %s %s", path, name);
    char *filename;
    if (is_quobyte_path(path, &filename, 1)) {
        int ret = quobyte_getxattr(filename, name, value, size);
        free(filename);
        ld_quobyte_try_fini();
        return ret;
    }
    return real_getxattr(path, name, value, size);
}

ssize_t (*real_lgetxattr)(const char *path, const char *name, void *value, size_t size) = NULL;
ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size) {
    LD_DLSYM(real_lgetxattr, lgetxattr, "lgetxattr");
    LD_QUOBYTE_DPRINTF("lgetxattr path=%s name=%s", path, name);
    char *filename;
    if (is_quobyte_path(path, &filename, 0)) {
        int ret = quobyte_getxattr(filename, name, value, size);
        free(filename);
        ld_quobyte_try_fini();
        return ret;
    }
    return real_lgetxattr(path, name, value, size);
}

int (*real_open)(__const char *path, int flags, ...);
int open(const char *path, int flags, ...)
{
    LD_DLSYM(real_open, open, "open");
    char *filename;
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    LD_QUOBYTE_DPRINTF("open path=%s flags=%d mode=0%o", path, flags, mode);
    if (is_quobyte_path(path, &filename, 0)) {
        int i, fd;
        struct quobyte_fh* fh = quobyte_open(filename, flags, mode);
        free(filename);
        if (!fh) {
            ld_quobyte_try_fini();
            return -1;
        }
        for (i = 0; i < QUOBYTE_MAX_FD; i++) {
            if (quobyte_fd_list[i].fd == -1) {
                fd = open("/dev/zero", O_RDONLY);
                assert(fd >= 0);
                LD_QUOBYTE_DPRINTF("assigning fake fd = %d for quobyte fh %p", fd, fh);
                quobyte_fd_list[i].fd = fd;
                quobyte_fd_list[i].fh = fh;
                quobyte_fd_list[i].offset = 0;
                struct stat statbuf;
                quobyte_fstat(fh, &statbuf);
                quobyte_fd_list[i].size = statbuf.st_size;
                break;
            }
        }
        assert(i < QUOBYTE_MAX_FD);
        return fd;
    }
    return real_open(path, flags, mode);
}

int (*real_dup2)(int oldfd, int newfd);
int dup2(int oldfd, int newfd)
{
    LD_DLSYM(real_dup2, dup2, "dup2");
    LD_QUOBYTE_DPRINTF("dup2 oldfd=%d newfd=%d", oldfd, newfd);
    struct quobyte_fd_list *e = is_quobyte_fd(oldfd);
    if (e) {
        e->fd = newfd;
    }
    return real_dup2(oldfd, newfd);
}

ssize_t (*real_read)(int fd, void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count) {
    LD_DLSYM(real_read, read, "read");
    LD_QUOBYTE_DPRINTF("read fd=%d buf=%p count=%d", fd, buf, (int) count);
    struct quobyte_fd_list *e = is_quobyte_fd(fd);
    if (e) {
        int ret = quobyte_read(e->fh, buf, e->offset, count);
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
    LD_QUOBYTE_DPRINTF("lseek fd=%d offset=%lu whence=%d", fd, offset, whence);
    struct quobyte_fd_list *e = is_quobyte_fd(fd);
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
    LD_QUOBYTE_DPRINTF("write fd=%d buf=%p count=%d", fd, buf, (int) count);
    struct quobyte_fd_list *e = is_quobyte_fd(fd);
    if (e) {
        int ret = quobyte_write(e->fh, buf, e->offset, count, 0);
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
    LD_QUOBYTE_DPRINTF("pread fd=%d buf=%p count=%d off=%ld", fd, buf, (int) count, offset);
    struct quobyte_fd_list *e = is_quobyte_fd(fd);
    if (e) {
        return quobyte_read(e->fh, buf, offset, count);
    }
    return real_read(fd, buf, count);
}

ssize_t (*real_pwrite)(int fd, const void *buf, size_t count, off_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    LD_DLSYM(real_pwrite, pwrite, "pwrite");
    LD_QUOBYTE_DPRINTF("pwrite fd=%d buf=%p count=%d off=%ld", fd, buf, (int) count, offset);
    struct quobyte_fd_list *e = is_quobyte_fd(fd);
    if (e) {
        return quobyte_write(e->fh, buf, offset, count, 0);
    }
    return real_write(fd, buf, count);
}

int (*real_fstat)(int fd, struct stat *buf);
int fstat(int fd, struct stat *buf) {
    LD_DLSYM(real_fstat, fstat, "fstat");
    LD_QUOBYTE_DPRINTF("fstat fd=%d", fd);
    struct quobyte_fd_list *e = is_quobyte_fd(fd);
    if (e) {
        return quobyte_fstat(e->fh, buf);
    }
    return real_fstat(fd, buf);
}

int (*real_fsync)(int fd) = NULL;
int fsync(int fd) {
    LD_DLSYM(real_fsync, fsync, "fsync");
    LD_QUOBYTE_DPRINTF("fsync fd=%d", fd);
    struct quobyte_fd_list *e = is_quobyte_fd(fd);
    if (e) {
        return quobyte_fsync(e->fh);
    }
    return real_fsync(fd);
}

int (*real_fdatasync)(int fd) = NULL;
int fdatasync(int fd) {
    LD_DLSYM(real_fdatasync, fdatasync, "fdatasync");
    LD_QUOBYTE_DPRINTF("fdatasync fd=%d", fd);
    struct quobyte_fd_list *e = is_quobyte_fd(fd);
    if (e) {
        return quobyte_fsync(e->fh);
    }
    return real_fdatasync(fd);
}

int (*real_ftruncate)(int fd, off_t length);
int ftruncate(int fd, off_t length) {
    LD_DLSYM(real_ftruncate, ftruncate, "ftruncate");
    LD_QUOBYTE_DPRINTF("ftruncate fd=%d length %lu", fd, length);
    struct quobyte_fd_list *e = is_quobyte_fd(fd);
    if (e) {
        return quobyte_ftruncate(e->fh, length);
    }
    return real_ftruncate(fd, length);
}

int (*real_close)(int fd);
int close(int fd)
{
    LD_DLSYM(real_close, close, "close");
    LD_QUOBYTE_DPRINTF("close fd=%d", fd);
    struct quobyte_fd_list *e = is_quobyte_fd(fd);
    if (e) {
        int ret;
        e->fd = -1;
        LD_QUOBYTE_DPRINTF("quobyte_close %p", e->fh);
        close(fd);
        ret = quobyte_close(e->fh);
        ld_quobyte_try_fini();
        return ret;
    }
    return real_close(fd);
}

int (*real_access)(const char *pathname, int mode);
int access(const char *pathname, int mode)
{
    LD_DLSYM(real_access, access, "access");
    LD_QUOBYTE_DPRINTF("access called %s %d", pathname, mode);
    char *filename;
    if (is_quobyte_path(pathname, &filename, 1)) {
        int ret = quobyte_access(filename, mode);
        free(filename);
        ld_quobyte_try_fini();
        return ret;
    }
    return real_access(pathname, mode);
}

int (*real_chmod)(const char* path, mode_t mode);
int chmod(const char* path, mode_t mode)
{
    LD_DLSYM(real_chmod, chmod, "chmod");
    LD_QUOBYTE_DPRINTF("chmod called %s %d", path, mode);
    char *filename;
    if (is_quobyte_path(path, &filename, 1)) {
        int ret = quobyte_chmod(filename, mode);
        free(filename);
        ld_quobyte_try_fini();
        return ret;
    }
    return real_chmod(path, mode);
}

int (*real_dirfd)(DIR *dirp);
int dirfd(DIR *dirp)
{
    LD_DLSYM(real_dirfd, dirfd, "dirfd");
    LD_QUOBYTE_DPRINTF("dirfd called %p", dirp);
    if (is_quobyte_dh(dirp)) {
        errno = ENOTSUP;
        return -1;
    }
    return real_dirfd(dirp);
}

int (*real_readdir_r)(DIR *dirp, struct dirent *entry, struct dirent **result);
int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result)
{
    LD_DLSYM(real_readdir_r, readdir_r, "readdir_r");
    LD_QUOBYTE_DPRINTF("readdir_r called %p entry=%p *result=%p", dirp, entry, *result);
    if (is_quobyte_dh(dirp)) {
        struct dirent *ret = readdir(dirp);
        if (ret) {
            memcpy(entry, ret, sizeof(struct dirent));
        }
        *result = ret;
        return 0;
    }
    return real_readdir_r(dirp, entry, result);
}

int (*real_statvfs)(const char *path, struct statvfs *buf);
int statvfs(const char *path, struct statvfs *buf)
{
    LD_DLSYM(real_statvfs, statvfs, "statvfs");
    LD_QUOBYTE_DPRINTF("statvfs called path %s buf %p", path, buf);
    char *filename;
    if (is_quobyte_path(path, &filename, 1)) {
        int ret = quobyte_statvfs(filename, buf);
        free(filename);
        ld_quobyte_try_fini();
        return ret;
    }
    return real_statvfs(path, buf);
}

int (*real_unlink)(const char *pathname);
int unlink(const char *pathname)
{
    LD_DLSYM(real_unlink, unlink, "unlink");
    LD_QUOBYTE_DPRINTF("unlink called path %s", pathname);
    char *filename;
    if (is_quobyte_path(pathname, &filename, 1)) {
        int ret = quobyte_unlink(filename);
        free(filename);
        ld_quobyte_try_fini();
        return ret;
    }
    return real_unlink(pathname);
}

int (*real_mkdir)(const char *path, mode_t mode);
int mkdir(const char *path, mode_t mode)
{
    LD_DLSYM(real_mkdir, mkdir, "mkdir");
    LD_QUOBYTE_DPRINTF("mkdir called path %s mode %o", path, mode);
    char *filename;
    if (is_quobyte_path(path, &filename, 1)) {
        int ret = quobyte_mkdir(filename, mode);
        free(filename);
        ld_quobyte_try_fini();
        return ret;
    }
    return real_mkdir(path, mode);
}

int (*real_rmdir)(const char* path);
int rmdir(const char* path)
{
    LD_DLSYM(real_rmdir, rmdir, "rmdir");
    LD_QUOBYTE_DPRINTF("rmdir called path %s", path);
    char *filename;
    if (is_quobyte_path(path, &filename, 1)) {
        int ret = quobyte_rmdir(filename);
        free(filename);
        ld_quobyte_try_fini();
        return ret;
    }
    return real_rmdir(path);
}

int (*real_rename)(const char *old, const char *new);
int rename(const char *old, const char *new)
{
    LD_DLSYM(real_rename, rename, "rename");
    LD_QUOBYTE_DPRINTF("rename called old %s new %s", old, new);
    char *filename_old, *filename_new;
    if (is_quobyte_path(old, &filename_old, 1)) {
        if (is_quobyte_path(new, &filename_new, 1)) {
            int ret = quobyte_rename(filename_old, filename_new);
            free(filename_old);
            free(filename_new);
            ld_quobyte_try_fini();
            return ret;
        } else {
            int ret = quobyte_rename(filename_old, new);
            free(filename_old);
            ld_quobyte_try_fini();
            return ret;
        }
    }
    return real_rename(old, new);
}
