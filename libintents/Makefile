PROGRAM=testintents
OBJECTS=
LIBRARIES= glib-2.0
CFLAGS= -g -Wall -O0 -std=c99 -D_GNU_SOURCE -DDEBUG `pkg-config --cflags $(LIBRARIES)`
LDLIBS= -L. -ldl `pkg-config --libs $(LIBRARIES)`
CC=gcc

all: lib test

lib: libintents.o
	$(CC) $(CFLAGS) -shared -Wl,-soname,libintents.so.1 -o libintents.so.1.0 libintents.o -L. -lmuacc $(LDLIBS)
	ln -sf libintents.so.1.0 libintents.so

libintents.o: libintents.c
	$(CC) $(CFLAGS) -fPIC -c libintents.c

test: testintents.o
	$(CC) $(CFLAGS) -o testintents testintents.o $(LDLIBS)

testintents.o: testintents.c
	$(CC) $(CFLAGS) -c testintents.c -o testintents.o

clean:
	rm -f testintents testintents.o libintents.so.1.0 libintents.o libintents.so
