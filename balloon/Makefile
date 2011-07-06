# $FreeBSD: src/sys/modules/joy/Makefile,v 1.15.2.3 2002/08/07 16:31:56 ru Exp $
# $DragonFly: src/sys/dev/misc/joy/Makefile,v 1.3 2005/09/10 10:08:42 swildner Exp $

#.PATH: ${.CURDIR}/../../../isa
KMOD    = virtio-net
CFLAGS += -I../
SRCS    = virtio-mb.c
SRCS            += bus_if.h device_if.h pci_if.h 

.include <bsd.kmod.mk>