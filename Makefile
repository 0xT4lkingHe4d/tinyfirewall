# Intended for linux-6.1.0-29

obj-m += tfirewall.o
KVER = $(shell uname -r)
PWD = $(shell pwd)

all:
	make -C /lib/modules/$(KVER)/build M=$(PWD) modules

clear:
	make -C /lib/modules/$(KVER)/build M=$(PWD) clean

load:
	sudo insmod tfirewall.ko

unload:
	sudo rmmod tfirewall.ko
