obj-m += antidetection.o
antidetection-objs := rootkit.o

KDIR=/lib/modules/$(shell uname -r)/build


default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean