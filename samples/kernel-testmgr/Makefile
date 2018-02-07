obj-m := testmgr.o

KERNELDIR = /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KERNELDIR) SUBDIRS=$(PWD)

clean:
	$(MAKE) -C $(KERNELDIR) SUBDIRS=$(PWD) clean