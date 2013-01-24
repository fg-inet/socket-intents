PROGRAM=testintents
OBJECTS=
CFLAGS= -g -Wall -O3 -std=c99
LDLIBS= -L. -ldl
CC=gcc

all: lib test

lib: libintents.o
	$(CC) $(CFLAGS) -shared -Wl,-soname,libintents.so.1 -o libintents.so.1.0 libintents.o
	ln -s libintents.so.1.0 libintents.so

libintents.o: libintents.c
	$(CC) $(CFLAGS) -fPIC -c libintents.c

test: testintents.o
	$(CC) $(CFLAGS) -o testintents testintents.o $(LDLIBS)

testintents.o: testintents.c
	$(CC) $(CFLAGS) -c testintents.c -o testintents.o

clean:
	rm -f testintents testintents.o libintents.so.1.0 libintents.o
