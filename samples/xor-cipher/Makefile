.PHONY: all clean static shared

all: static testmgr shared

static: libxor_cipher.a

libxor_cipher.a: xor_cipher.o
	ar rcs libxor_cipher.a xor_cipher.o

xor_cipher.o: xor_cipher.c
	gcc $^ -c -I. -Wall -Wextra -fPIC

testmgr: libxor_cipher.a testmgr.o
	gcc testmgr.o -o $@ -L. -lxor_cipher

testmgr.o: testmgr.c
	gcc $^ -c -I. -Wall -Wextra

shared: libxor_cipher.so

libxor_cipher.so: xor_cipher.o
	gcc $^ -o $@ -shared

clean:
	rm -rvf testmgr libxor_cipher.a libxor_cipher.so xor_cipher.o testmgr.o 