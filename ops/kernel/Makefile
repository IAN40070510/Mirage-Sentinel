obj-m += mirage_cgroup_audit.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all clean load unload status

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load: all
	sudo insmod mirage_cgroup_audit.ko

unload:
	sudo rmmod mirage_cgroup_audit

status:
	cat /proc/mirage_cgroup_audit
