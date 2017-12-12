# Makefile -	"Production" Makefile for backy-io

PROG =		backy-io

MAIN_OBJ =	backy-io.o
EXT_OBJ  =  json-parser/json.o minilzo/minilzo.o smhasher/src/MurmurHash3.o

TARGETS =	$(PROG)

ARCH =		
COPT =		-msse4.2 -g
LFS_FLAGS =	-D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -DJSON_TRACK_SOURCE

CFLAGS =	$(ARCH) $(COPT) $(LFS_FLAGS) -Wunused-function -Wunused-label -Wunused-value -Wunused-variable 

#------------------------------------------------------------------------

LDFLAGS =	$(ARCH) -O3 -pthread

#------------------------------------------------------------------------

all : $(PROG)

$(PROG) : $(MAIN_OBJ) $(EXT_OBJ)
	$(CC) -o $@ $(EXT_OBJ) $(MAIN_OBJ) $(LDFLAGS)

quobyte-backy-prepare : quobyte-backy-prepare.o $(EXT_OBJ)
	$(CC) -o $@ $(EXT_OBJ) quobyte-backy-prepare.o $(LDFLAGS) -lquobyte -lreadline

debug : debug.o $(EXT_OBJ)
	$(CC) -o $@ $(EXT_OBJ) debug.o $(LDFLAGS)

clean :
	rm -f $(TARGETS) $(MAIN_OBJ) $(EXT_OBJ) *.o
