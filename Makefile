# Makefile -	"Production" Makefile for backy-io

PROG =		backy-io

MAIN_OBJ =	backy-io.o
EXT_OBJ  =  json-parser/json.o minilzo/minilzo.o smhasher/src/MurmurHash3.o

TARGETS =	$(PROG)

ARCH =		
COPT =		-msse4.2 -g
LFS_FLAGS =	-D_GNU_SOURCE -DJSON_TRACK_SOURCE

CFLAGS =	$(ARCH) $(COPT) $(LFS_FLAGS) -Wunused-function -Wunused-label -Wunused-value -Wunused-variable 

#------------------------------------------------------------------------

LDFLAGS =	$(ARCH) -O3 -pthread

#------------------------------------------------------------------------

all : $(PROG)

$(PROG) : $(MAIN_OBJ) $(EXT_OBJ)
	$(CC) -o $@ $(EXT_OBJ) $(MAIN_OBJ) $(LDFLAGS)

backy-io-test : backy-io.o $(EXT_OBJ)
	$(CC) -o $@ $(EXT_OBJ) backy-io.o $(LDFLAGS) -lquobyte -lreadline

backy-estimate : backy-estimate.o $(EXT_OBJ)
	$(CC) -o $@ $(EXT_OBJ) backy-estimate.o $(LDFLAGS)

rbd-backy-prepare : rbd-backy-prepare.o $(EXT_OBJ)
	$(CC) -o $@ $(EXT_OBJ) rbd-backy-prepare.o $(LDFLAGS) -lrbd -lrados

rbd-backy-scrub : rbd-backy-scrub.o $(EXT_OBJ)
	$(CC) -o $@ $(EXT_OBJ) rbd-backy-scrub.o $(LDFLAGS) -lrbd -lrados

json-test : json-test.o $(EXT_OBJ)
	$(CC) -o $@ $(EXT_OBJ) json-test.o $(LDFLAGS)

chunktool : chunktool.o $(EXT_OBJ)
	$(CC) -o $@ $(EXT_OBJ) chunktool.o $(LDFLAGS)

debug : debug.o $(EXT_OBJ)
	$(CC) -o $@ $(EXT_OBJ) debug.o $(LDFLAGS)

clean :
	rm -f $(TARGETS) $(MAIN_OBJ) $(EXT_OBJ) *.o
