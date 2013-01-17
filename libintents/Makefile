all: lib test

lib: libintents.o
	gcc -g -shared -Wl,-soname,libintents.so.1 -o libintents.so.1.0 libintents.o -lc

libintents.o: libintents.c
	gcc -fPIC -Wall -g -c libintents.c

test: testintents.o
	gcc -g -o testintents testintents.o -L. -ldl

testintents.o: testintents.c
	gcc -Wall -g -c testintents.c -o testintents.o

clean:
	rm -f testintents testintents.o libintents.so.1.0 libintents.o
