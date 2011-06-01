# $FreeBSD: src/sys/modules/joy/Makefile,v 1.15.2.3 2002/08/07 16:31:56 ru Exp $
# $DragonFly: src/sys/dev/misc/joy/Makefile,v 1.3 2005/09/10 10:08:42 swildner Exp $

#.PATH:	${.CURDIR}/../../../isa
KMOD	= virtio-blk
CFLAGS += -I../ 
#CFLAGS += -DVIRTIO_DEBUG
CFLAGS += -g
SRCS	= virtio-blk.c
SRCS		+= bus_if.h device_if.h pci_if.h
#SRCS+=	device_if.h bus_if.h pci_if.h
#SRCS+=	opt_scsi.h opt_cam.h opt_aac.h

.include <bsd.kmod.mk>
