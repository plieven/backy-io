#include "backy.h"

#define BLOCKSIZE (1 << 20)
#include "minilzo/minilzo.h"

int main(int argc, char** argv) {
    int ret = 1;
    char *buf = NULL, *buf2 = NULL, *work_buf = NULL;
    size_t bytes = 0;
    ssize_t r = 0;
    if (argc < 2) goto usage;
    while (1) {
        buf = realloc(buf, bytes + 65536);
        assert(buf);
        r = read(0, buf + bytes, 65536);
        assert (r >= 0);
        if (r == 0) break;
        bytes += r;
    }
    fprintf(stderr, "read %lu bytes\n", bytes);
    if (!strcmp("-d", argv[1])) {
        size_t decompressed_size = 0;
        if (buf[0] & 0xff != 0xf0) {
            fprintf(stderr, "lzo header error (magic): expected 0xf0 got 0x%02x\n", buf[0] & 0xff);
            goto out;
        }
        decompressed_size = (buf[1] << 24) | (buf[2] << 16) | (buf[3] << 8) | buf[4];
        fprintf(stderr, "decompressed size %lu bytes\n", decompressed_size);
        buf2 = malloc(decompressed_size);
        unsigned long buf2_size = decompressed_size;
        assert(buf2);
        /* Decompress */
        ret = lzo1x_decompress_safe(
            (const unsigned char *) buf + 5,
            bytes - 5,
            (unsigned char *) buf2,
            (unsigned long *) &buf2_size,
            NULL);
        ret = -ret;
        if (ret != LZO_E_OK && ret != 8) {
            fprintf(stderr, "lzo1x_decompress failed, return     = %d\n", ret);
            fprintf(stderr, "buf2_size = %lu\n", buf2_size);
            goto out;
        } else if (ret == 8) {
            fprintf(stderr, "WARN: input not consumed\n");
        }
        char hash[DEDUP_MAC_SIZE_BYTES];
        char hash_c[DEDUP_MAC_SIZE_STR] = {};
        assert(buf2_size == decompressed_size);
        mmh3(buf2, decompressed_size, 0, &hash[0]);
        dedup_hash_sprint(&hash[0], hash_c);
        fprintf(stderr, "hash %s (%s)\n", hash_c, DEDUP_MAC_NAME);
        XXH128_hash_t x = XXH3_128bits(buf2, decompressed_size);
        XXH128_canonicalFromHash((void*)&hash[0], x);
        dedup_hash_sprint(&hash[0], hash_c);
        fprintf(stderr, "hash %s (%s)\n", hash_c, DEDUP_MAC_NAME_XXH3);
        if (argc >=3 && !strcmp("-o", argv[2])) {
            write(1, buf2, decompressed_size);
            fprintf(stderr, "wrote %lu bytes to stdout\n", decompressed_size);
        }
        goto out;
    }
    if (!strcmp("-c", argv[1])) {
        char hash[DEDUP_MAC_SIZE_BYTES];
        char hash_c[DEDUP_MAC_SIZE_STR] = {};
        mmh3(buf, bytes, 0, &hash[0]);
        dedup_hash_sprint(&hash[0], hash_c);
        fprintf(stderr, "hash %s (%s)\n", hash_c, DEDUP_MAC_NAME);
        XXH128_hash_t x = XXH3_128bits(buf, bytes);
        XXH128_canonicalFromHash((void*)&hash[0], x);
        dedup_hash_sprint(&hash[0], hash_c);
        fprintf(stderr, "hash %s (%s)\n", hash_c, DEDUP_MAC_NAME_XXH3);
        work_buf = malloc(LZO1X_1_MEM_COMPRESS);
        assert(work_buf);
        unsigned long buf2_bytes = bytes + bytes / 16 + 64 + 3 + 5;
        buf2 = malloc(buf2_bytes);
        assert(buf2);
        ret = lzo1x_1_compress(
            (unsigned char *) buf,
            bytes,
            (unsigned char *) buf2 + 5,
            (unsigned long *) &buf2_bytes,
            work_buf);
        if (ret != LZO_E_OK) {
            fprintf(stderr, "lzo1x_compress failed, return     = %d\n", ret);
            goto out;
        }
        buf2[0] = 0xf0;
        buf2[1] = (bytes >> 24) & 0xff;
        buf2[2] = (bytes >> 16) & 0xff;
        buf2[3] = (bytes >> 8) & 0xff;
        buf2[4] = bytes & 0xff;
        buf2_bytes += 5;
        fprintf(stderr, "compressed size %lu\n", buf2_bytes);
        if (argc >=3 && !strcmp("-o", argv[2])) {
            write(1, buf2, buf2_bytes);
            fprintf(stderr, "wrote %lu bytes to stdout\n", buf2_bytes);
        }
        goto out;
    }

usage:
    fprintf(stderr, "Usage: %s -c|-d [-o]\n", argv[0]);
    fprintf(stderr, " -c  compress\n");
    fprintf(stderr, " -d  decompress\n");
    fprintf(stderr, " -o  dump binary result to stdout\n");
    ret = 1;
out:
    free(buf);
    free(buf2);
    free(work_buf);
    exit(ret);
}
