/*	$NetBSD$	*/

/*
 * Copyright (c) 2010 Minoura Makoto.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Part of the file derived from `Virtio PCI Card Specification v0.8.6 DRAFT'
 * Appendix A.
 */
/* An interface for efficient virtio implementation.
 *
 * This header is BSD licensed so anyone can use the definitions
 * to implement compatible drivers/servers.
 *
 * Copyright 2007, 2009, IBM Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _VIRTIOVAR_H_
#define	_VIRTIOVAR_H_

//#define VIRTIO_DEBUG 1
#ifdef VIRTIO_DEBUG 
# define debug(fmt, args...)	do {kprintf("%s: " fmt, __func__ , ##args);} while(0)
#else
# define debug( fmt, args...)
#endif

//#include "virtioreg.h"
/* Packet header structure */
struct virtio_net_hdr {
	uint8_t		flags;
	uint8_t		gso_type;
	uint16_t	hdr_len;
	uint16_t	gso_size;
	uint16_t	csum_start;
	uint16_t	csum_offset;
#if 0
	uint16_t	num_buffers; /* if VIRTIO_NET_F_MRG_RXBUF enabled */
#endif
} __packed;

struct vq_entry {
	TAILQ_ENTRY(vq_entry)	qe_list; /* free list */
	uint16_t		qe_index; /* index in vq_desc array */
	/* followings are used only when it is the `head' entry */
	int16_t			qe_next;     /* next enq slot */
	bool			qe_indirect; /* 1 if using indirect */
	struct vring_desc	*qe_desc_base;
};

struct virtqueue {
	struct virtio_softc	*vq_owner;
        unsigned int		vq_num; /* queue size (# of entries) */
	int			vq_index; /* queue number (0, 1, ...) */

	/* vring pointers (KVA) */
        struct vring_desc	*vq_desc;
        struct vring_avail	*vq_avail;
        struct vring_used	*vq_used;
	void			*vq_indirect;

	/* virtqueue allocation info */
	void			*vq_vaddr;
	int			vq_availoffset;
	int			vq_usedoffset;
	int			vq_indirectoffset;
	bus_dma_segment_t	vq_segs[1];
	unsigned int		vq_bytesize;
	bus_dma_tag_t		vq_dmat;
	bus_dmamap_t		vq_dmamap;
	bus_addr_t			bus_addr;

	int			vq_maxsegsize;
	int			vq_maxnsegs;

	/* free entry management */
	struct vq_entry		*vq_entries;
	TAILQ_HEAD(, vq_entry) vq_freelist;
	struct spinlock		vq_freelist_lock;

	/* enqueue/dequeue status */
	uint16_t		vq_avail_idx;
	uint16_t		vq_used_idx;
	int			vq_queued;
	struct spinlock		vq_aring_lock;
	struct spinlock		vq_uring_lock;

	/* interrupt handler */
	int			(*vq_done)(struct virtqueue*);

};

struct virtio_softc {
	device_t dev;
	int rid_ioport;
	int rid_memory;
	int rid_irq;

	int regs_rid; /* resource id*/
	struct resource* res_memory;    /* Resource for mem range. */
	struct resource* res_irq;   /* Resource for irq range. */
	struct resource* io; 

    bus_dma_tag_t       virtio_dmat;/*Master tag*/

    int         sc_config_offset;

	bus_space_tag_t		sc_iot;
	bus_space_handle_t	sc_ioh;

  	int			sc_nvqs; /* set by child */
	struct virtqueue *sc_vqs;

	bus_dma_tag_t requests_dmat;
	bus_dmamap_t cmds_dmamap;
    bus_dma_tag_t payloads_dmat;

    vm_paddr_t phys_next;       /* next page from mem range */
	uint32_t 	sc_features;
	bool sc_indirect;
	int			sc_childdevid;
	device_t		sc_child; /* set by child */
	//struct virtqueue *sc_vqs;
	void * virtio_intr;

	int         (*sc_config_change)(struct virtio_softc*);
	/* set by child */
	int         (*sc_intrhand)(struct virtio_softc*);
	/* set by child */
} *sc;


static const char *virtio_device_name[] = {
	"Unknown (0)",		/* 0 */
	"Network",		/* 1 */
	"Block",		/* 2 */
	"Console",		/* 3 */
	"Entropy",		/* 4 */
	"Memory Balloon",	/* 5 */
	"Unknown (6)",		/* 6 */
	"Unknown (7)",		/* 7 */
	"Unknown (8)",		/* 8 */
	"9P Transport"		/* 9 */
};

#define NDEVNAMES	(sizeof(virtio_device_name)/sizeof(char*))

#define kassert(exp) do { if (__predict_false(!(exp)))	\
					panic("assertion: %s in %s",	\
					#exp, __func__); } while (0)
#define MINSEG_INDIRECT     2 /* use indirect if nsegs >= this value */




int
virtio_enqueue_p(struct virtio_softc *sc, struct virtqueue *vq, int slot, 
				 bus_addr_t	ds_addr, bus_size_t	ds_len,		
				 bus_dmamap_t dmamap, bus_addr_t start, bus_size_t len,	
				 bool write);
int
virtio_enqueue(struct virtio_softc *sc, struct virtqueue *vq, int slot, 
			   bus_dma_segment_t *segs, int nseg,
			   bus_dmamap_t dmamap, 
			   bool write);
int virtio_enqueue_prep(struct virtio_softc*, struct virtqueue*, int*);
void virtio_set_status(struct virtio_softc *sc, int );
uint32_t virtio_negotiate_features(struct virtio_softc*, uint32_t);
void virtio_write_device_config_1(struct virtio_softc *sc, int index, uint8_t value);
uint16_t virtio_read_device_config_2(struct virtio_softc *sc, int index);
uint32_t virtio_read_device_config_4(struct virtio_softc *sc, int index);
uint64_t virtio_read_device_config_8(struct virtio_softc *sc, int index);
uint8_t virtio_read_device_config_1(struct virtio_softc *sc, int index);
int virtio_alloc_vq(struct virtio_softc*, struct virtqueue*, int, int, int,
		    const char*);
int virtio_free_vq(struct virtio_softc*, struct virtqueue*);
void virtio_reset(struct virtio_softc *);
int virtio_enqueue_reserve(struct virtio_softc*, struct virtqueue*, int, int);
int virtio_enqueue_commit(struct virtio_softc*, struct virtqueue*, int, bool);
void virtio_stop_vq_intr(struct virtio_softc *, struct virtqueue *);
void virtio_start_vq_intr(struct virtio_softc *, struct virtqueue *);
int virtio_dequeue_commit(struct virtio_softc*, struct virtqueue*, int);
int virtio_dequeue(struct virtio_softc*, struct virtqueue*, int *, int *);
int virtio_vq_intr(struct virtio_softc *);

#endif /* _VIRTIOVAR_H_ */
