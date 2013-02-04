PROGRAM=testintents
OBJECTS=
LIBRARIES= glib-2.0
CFLAGS= -g -Wall -O0 -std=c99 -D_GNU_SOURCE `pkg-config --cflags $(LIBRARIES)`
LDLIBS= -L. -ldl `pkg-config --libs $(LIBRARIES)`
CC=gcc

all: lib test

lib: libintents.o muacc.o tlv.o
	$(CC) $(CFLAGS) -shared -Wl,-soname,libintents.so.1 -o libintents.so.1.0 libintents.o ../clib/muacc.o -L. -lmuacc $(LDLIBS)
	ln -sf libintents.so.1.0 libintents.so

muacc: muacctest.o
	$(CC) $(CFLAGS) -o muacctest muacctest.o ../clib/tlv.o $(LDLIBS)

libintents.o: libintents.c
	$(CC) $(CFLAGS) -fPIC -c libintents.c

muacc.o: ../clib/muacc.c
	$(CC) $(CFLAGS) -DHAVE_CONFIG_H -I. --pedantic -c -o ../clib/muacc.o ../clib/muacc.c

muacctest.o: ../clib/muacc.c
	$(CC) $(CFLAGS) -DHAVE_CONFIG_H -D_TEST_MUACC_LIB -I. --pedantic -c -o muacctest.o ../clib/muacc.c

tlv.o: ../clib/tlv.c
	$(CC) -DHAVE_CONFIG_H -I. --pedantic -c -o ../clib/tlv.o ../clib/tlv.c

test: testintents.o
	$(CC) $(CFLAGS) -o testintents testintents.o $(LDLIBS)

testintents.o: testintents.c
	$(CC) $(CFLAGS) -c testintents.c -o testintents.o

clean:
	rm -f testintents testintents.o libintents.so.1.0 libintents.o libintents.so ../clib/tlv.o ../clib/muacc.o
