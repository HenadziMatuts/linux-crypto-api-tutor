.PHONY: all clean

all: testmgr

testmgr: testmgr.o
	gcc $^ -o $@

testmgr.o: testmgr.c
	gcc $^ -c -I. -Wall -Wextra

clean:
	rm -rvf testmgr.o testmgr