# Makefile -	"Production" Makefile for backy-io

PROG =		backy-io

MAIN_OBJ =	backy-io.o
EXT_OBJ  =  jsmn/jsmn.o minilzo/minilzo.o

TARGETS =	$(PROG)

ARCH =		
COPT =		-msse4.2  -g
LFS_FLAGS =	-D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

CFLAGS =	$(ARCH) $(COPT) $(LFS_FLAGS) -Wunused-function -Wunused-label -Wunused-value -Wunused-variable 

#------------------------------------------------------------------------

LDFLAGS =	$(ARCH) -O3 -pthread

#------------------------------------------------------------------------

all : $(PROG)

$(PROG) : $(MAIN_OBJ) $(EXT_OBJ)
	$(CC) -o $@ $(MAIN_OBJ) $(EXT_OBJ) $(LDFLAGS)

clean :
	rm -f $(TARGETS) *.o
