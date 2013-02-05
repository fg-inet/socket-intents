PROGRAM=testintents
OBJECTS=
LIBRARIES= glib-2.0
CFLAGS= -g -Wall -O0 -std=c99 -DDEBUG -D_GNU_SOURCE `pkg-config --cflags $(LIBRARIES)`
LDLIBS= -L. -ldl `pkg-config --libs $(LIBRARIES)`
CC=gcc

all: lib test

lib: libintents.o muacc.o muacc_ctx.o muacc_tlv.o muacc_util.o
	$(CC) $(CFLAGS) -shared -Wl,-soname,libintents.so.1 -o libintents.so.1.0 libintents.o ../clib/muacc.o ../clib/muacc_ctx.o ../clib/muacc_tlv.o ../clib/muacc_util.o -L. -lmuacc $(LDLIBS)
	ln -sf libintents.so.1.0 libintents.so

muacc: muacctest.o
	$(CC) $(CFLAGS) -o muacctest muacctest.o ../clib/tlv.o $(LDLIBS)

libintents.o: libintents.c
	$(CC) $(CFLAGS) -fPIC -c libintents.c

muacc.o: ../clib/muacc.c
	$(CC) $(CFLAGS) -DHAVE_CONFIG_H -DCLIB_IF_NOISY_DEBUG=1 -I. --pedantic -c -o ../clib/muacc.o ../clib/muacc.c

muacctest.o: ../clib/muacc.c
	$(CC) $(CFLAGS) -DHAVE_CONFIG_H -D_TEST_MUACC_LIB -I. --pedantic -c -o muacctest.o ../clib/muacc.c

muacc_ctx.o: ../clib/muacc_ctx.c
	$(CC) $(CFLAGS) -DHAVE_CONFIG_H -DCLIB_CTX_NOISY_DEBUG=1 -I. --pedantic -c -o ../clib/muacc_ctx.o ../clib/muacc_ctx.c

muacc_tlv.o: ../clib/muacc_tlv.c
	$(CC) $(CFLAGS) -DHAVE_CONFIG_H -DCLIB_TLV_NOISY_DEBUG=1 -I. --pedantic -c -o ../clib/muacc_tlv.o ../clib/muacc_tlv.c

muacc_util.o: ../clib/muacc_util.c
	$(CC) $(CFLAGS) -DHAVE_CONFIG_H -DCLIB_UTIL_NOISY_DEBUG=1 -I. --pedantic -c -o ../clib/muacc_util.o ../clib/muacc_util.c

test: testintents.o
	$(CC) $(CFLAGS) -o testintents testintents.o $(LDLIBS)

testintents.o: testintents.c
	$(CC) $(CFLAGS) -c testintents.c -o testintents.o

clean:
	rm -f testintents testintents.o libintents.so.1.0 libintents.o libintents.so ../clib/tlv.o ../clib/muacc.o
