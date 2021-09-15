set -e
gcc -Wall -fPIC -shared -o ld_rbd.so ld_rbd.c -lrbd -lrados
gcc -Wall -fPIC -shared -DDEBUG -o ld_rbd_debug.so ld_rbd.c -lrbd -lrados
