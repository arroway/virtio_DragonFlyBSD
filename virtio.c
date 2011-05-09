/* NOTES
 *
 * virtio_probe()
 *
 * **
 * virtio_alloc_vq()
 * virtio_attach()
 *
 */


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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/uio.h>
#include <sys/fbio.h>
#include <sys/linker_set.h>
#include <sys/device.h>
#include <sys/thread2.h>
#include <sys/rman.h>

#include <sys/spinlock.h>
#include <sys/spinlock2.h>

#include <bus/pci/pcivar.h>
#include <bus/pci/pcireg.h>

#include "virtiovar.h"
#include "virtioreg.h"

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
void virtio_set_status(struct virtio_softc *sc, int status)
{
	int old = 0;

	if (status != 0)
		old = bus_space_read_1(sc->sc_iot, sc->sc_ioh,
				       VIRTIO_CONFIG_DEVICE_STATUS);
	//kprintf("%s: old:%d status:%d\n",__FUNCTION__,old,status);
	bus_space_write_1(sc->sc_iot, sc->sc_ioh, VIRTIO_CONFIG_DEVICE_STATUS,
			  status|old);
	//kprintf("%s: new old:%d status:%d\n",__FUNCTION__,old,status);
}
#define virtio_device_reset(sc)	virtio_set_status((sc), 0)
/*
 * Reset the device.
 */
/*
 * To reset the device to a known state, do following:
 *	virtio_reset(sc);	     // this will stop the device activity
 *	<dequeue finished requests>; // virtio_dequeue() still can be called
 *	<revoke pending requests in the vqs if any>;
 *	virtio_reinit_begin(sc);     // dequeue prohibitted
 *	newfeatures = virtio_negotiate_features(sc, requestedfeatures);
 *	<some other initialization>;
 *	virtio_reinit_end(sc);	     // device activated; enqueue allowed
 * Once attached, feature negotiation can only be allowed after virtio_reset.
 */
void
virtio_reset(struct virtio_softc *sc)
{
	virtio_device_reset(sc);
}
static inline void
vq_sync_uring(struct virtio_softc *sc, struct virtqueue *vq, int ops)
{
	bus_dmamap_sync(sc->requests_dmat, vq->vq_dmamap,
			//vq->vq_usedoffset,
			//offsetof(struct vring_used, ring)
			 //+ vq->vq_num * sizeof(struct vring_used_elem),
			ops);
}

static inline void
vq_sync_aring(struct virtio_softc *sc, struct virtqueue *vq, int ops)
{
	bus_dmamap_sync(sc->requests_dmat, vq->vq_dmamap,
			//vq->vq_availoffset,
			//offsetof(struct vring_avail, ring)
			 //+ vq->vq_num * sizeof(uint16_t),
			ops);
}


/*
 * Initialize vq structure.
 */
static void
virtio_init_vq(struct virtio_softc *sc, struct virtqueue *vq)
{
	int i, j;
	int vq_size = vq->vq_num;

	memset(vq->vq_vaddr, 0, vq->vq_bytesize);

	/* build the indirect descriptor chain */
	if (vq->vq_indirect != NULL) {
		struct vring_desc *vd;

		for (i = 0; i < vq_size; i++) {
			vd = vq->vq_indirect;
			vd += vq->vq_maxnsegs * i;
			for (j = 0; j < vq->vq_maxnsegs-1; j++)
				vd[j].next = j + 1;
		}
	}

	/* free slot management */
	TAILQ_INIT(&vq->vq_freelist);
	for (i = 0; i < vq_size; i++) {
		TAILQ_INSERT_TAIL(&vq->vq_freelist,
				    &vq->vq_entries[i], qe_list);
		vq->vq_entries[i].qe_index = i;
	}
	spin_init(&vq->vq_freelist_lock);

	/* enqueue/dequeue status */
	vq->vq_avail_idx = 0;
	vq->vq_used_idx = 0;
	vq->vq_queued = 0;
	spin_init(&vq->vq_aring_lock);
	spin_init(&vq->vq_uring_lock);
	vq_sync_aring(sc, vq, BUS_DMASYNC_PREWRITE);
	vq_sync_uring(sc, vq, BUS_DMASYNC_PREREAD);
	vq->vq_queued++;
}
static void
virtio_helper(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct virtqueue *vq = (struct virtqueue *) arg;
    debug("%s %u\n",__FUNCTION__,(uint)segs->ds_addr);

    vq->bus_addr = segs->ds_addr;
}

int
virtio_free_vq(struct virtio_softc *sc, struct virtqueue *vq)
{
	struct vq_entry *qe;
	int i = 0;

	/* device must be already deactivated */
	/* confirm the vq is empty */
	TAILQ_FOREACH(qe, &vq->vq_freelist, qe_list) {
		i++;
	}
	if (i != vq->vq_num) {
		kprintf("%s: freeing non-empty vq, index %d\n",
		        __func__,vq->vq_index);
		return EBUSY;
	}

	/* tell device that there's no virtqueue any longer */
	bus_space_write_2(sc->sc_iot, sc->sc_ioh,
			  VIRTIO_CONFIG_QUEUE_SELECT, vq->vq_index);
	bus_space_write_4(sc->sc_iot, sc->sc_ioh,
			  VIRTIO_CONFIG_QUEUE_ADDRESS, 0);

	kfree(vq->vq_entries, M_DEVBUF);
	spin_uninit(&vq->vq_freelist_lock);
	spin_uninit(&vq->vq_uring_lock);
	spin_uninit(&vq->vq_aring_lock);

	return 0;
}

int
virtio_alloc_vq(struct virtio_softc *sc,
		struct virtqueue *vq, int index, int maxsegsize, int maxnsegs,
		const char *name)
{
	int vq_size, allocsize1, allocsize2, allocsize3, allocsize = 0;
	int  r;
#define VIRTQUEUE_ALIGN(n)	(((n)+(VIRTIO_PAGE_SIZE-1))& ~(VIRTIO_PAGE_SIZE-1))
	debug("ind:%d, %d %d\n",index,(unsigned int)sc->sc_iot, (unsigned int)sc->sc_ioh);
	memset(vq, 0, sizeof(*vq));


	/*!  bus_space_write_2(space, handle, offset, value)
	 *   The bus_space_write_N() family of functions writes a 1, 2, 4, or 8 byte
	 *   data item to the offset specified by offset into the region specified by
	 *   handle of the bus space specified by space. The location being written
	 *   must lie within the bus space region specified by handle.
	 *
	 *   Write operations done by the bus_space_write_N() functions may be exe-
     *   cuted out of order with respect to other pending read and write opera-
     *   tions unless order is enforced by use of the bus_space_barrier() func-
     *   tion.
	 *   These functions will never fail.
	 */



	bus_space_write_2(sc->sc_iot, sc->sc_ioh,
			  VIRTIO_CONFIG_QUEUE_SELECT, index);
	vq_size = bus_space_read_2(sc->sc_iot, sc->sc_ioh,
				   VIRTIO_CONFIG_QUEUE_SIZE);
	if (vq_size == 0) {
		panic( "virtqueue not exist, index %d for %s\n",
				 index, name);
	}

	/*! #define VIRTIO_PAGE_SIZE	(4096)
	 *  #define VIRTQUEUE_ALIGN(n)	(((n)+(VIRTIO_PAGE_SIZE-1))& ~(VIRTIO_PAGE_SIZE-1))
	 */


	/* allocsize1: descriptor table + avail ring + pad */
	allocsize1 = VIRTQUEUE_ALIGN(sizeof(struct vring_desc)*vq_size
				     + sizeof(uint16_t)*(2+vq_size));
	/* allocsize2: used ring + pad */
	allocsize2 = VIRTQUEUE_ALIGN(sizeof(uint16_t)*2
				     + sizeof(struct vring_used_elem)*vq_size);
	/* allocsize3: indirect table */
	if (sc->sc_indirect && maxnsegs >= MINSEG_INDIRECT)
		allocsize3 = sizeof(struct vring_desc) * maxnsegs * vq_size;
	else
		allocsize3 = 0;
	allocsize = allocsize1 + allocsize2 + allocsize3;
	debug("a1:%d a2:%d a3:%d a4:%d\n",
			allocsize1, allocsize2,allocsize3, allocsize);


	/*!  (freebsd man)
	 *   bus_dma_tag_t
              A machine-dependent (MD) opaque type that describes the charac-
              teristics of DMA transactions.  DMA tags are organized into a
              hierarchy, with each child tag inheriting the restrictions of
              its parent.  This allows all devices along the path of DMA
              transactions to contribute to the constraints of those transac-
              tions.
	 *   bus_dma_tag_t virtio_dmat;
	 */

	int error;
	if (sc->virtio_dmat== NULL){
		kprintf("dmat is null\n");
		return 1;
	}

	/*!
	 *
	 *
	 * bus_dma_tag_create(parent, alignment, boundary, lowaddr, highaddr,
              *filtfunc, *filtfuncarg, maxsize, nsegments, maxsegsz, flags,
              *dmat)
              Allocates a device specific DMA tag, and initializes it accord-
              ing to the arguments provided:
              parent        Indicates restrictions between the parent bridge,
                            CPU memory, and the device.  May be NULL, if no
                            DMA restrictions are to be inherited.
              alignment     Alignment constraint, in bytes, of any mappings
                            created using this tag.  The alignment must be a
                            power of 2.  Hardware that can DMA starting at any
                            address would specify 1 for byte alignment.  Hard-
                            ware requiring DMA transfers to start on a multi-
                            ple of 4K would specify 4096.

      /*? valeur d'alignment = VIRTIO_PAGE_SIZE = 4096 ?

              boundary      Boundary constraint, in bytes, of the target DMA
                            memory region.  The boundary indicates the set of
                            addresses, all multiples of the boundary argument,
                            that cannot be crossed by a single
                            bus_dma_segment_t.  The boundary must be either a
                            power of 2 or 0.  `0' indicates that there are no
                            boundary restrictions.
              lowaddr
              highaddr      Bounds of the window of bus address space that
                            cannot be directly accessed by the device.  The
                            window contains all address greater than lowaddr
                            and less than or equal to highaddr.  For example,
                            a device incapable of DMA above 4GB, would specify
                            a highaddr of BUS_SPACE_MAXADDR and a lowaddr of
                            BUS_SPACE_MAXADDR_32BIT.  Similarly a device that
                            can only dma to addresses bellow 16MB would spec-
                            ify a highaddr of BUS_SPACE_MAXADDR and a lowaddr
                            of BUS_SPACE_MAXADDR_24BIT.  Some implementations
                            requires that some region of device visible
                            address space, overlapping available host memory,
                            be outside the window.  This area of `safe memory'
                            is used to bounce requests that would otherwise
                            conflict with the exclusion window.

        /*? ici, lowaddr = highaddr (= BUS_SPACE_MAXADDR = 4GB) ?

              filtfunc      Optional filter function (may be NULL) to be
                            called for any attempt to map memory into the win-
                            dow described by lowaddr and highaddr. A filter
                            function is only required when the single window
                            described by lowaddr and highaddr cannot ade-
                            quately describe the constraints of the device.
                            The filter function will be called for every
                            machine page that overlaps the exclusion window.
              filtfuncarg   Argument passed to all calls to the filter func-
                            tion for this tag.  May be NULL.
              maxsegsz      Maximum size, in bytes, of a segment in any DMA
                            mapped region associated with dmat.
              maxsize       Maximum size, in bytes, of the sum of all segment
                            lengths in a given DMA mapping associated with
                            this tag.
              nsegments     Number of discontinuities (scatter/gather seg-
                            ments) allowed in a DMA mapped region.  If there
                            is no restriction, BUS_SPACE_UNRESTRICTED may be
                            specified.
              flags         Are as follows:
                            BUS_DMA_ALLOCNOW  Allocate the resources necessary
                                              to guarantee that all map load
                                              operations associated with this
                                              tag will not block.  If suffi-
                                              cient resources are not avail-
                                              able, ENOMEM is returned.
              dmat          Pointer to a bus_dma_tag_t where the resulting DMA
                            tag will be stored.

              Returns ENOMEM if sufficient memory is not available for tag
              creation or allocating mapping resources.
	 */

	error = bus_dma_tag_create(sc->virtio_dmat,
			VIRTIO_PAGE_SIZE,
			0,
			BUS_SPACE_MAXADDR,
			BUS_SPACE_MAXADDR,
			NULL, NULL,
			allocsize,
			1,
			allocsize,
			BUS_DMA_NOWAIT,
			&vq->vq_dmat);
	if (error) {
		kprintf("could not allocate RX mbuf dma tag\n");
		return error;
	}

	/*error = bus_dmamap_create(vq->vq_dmat, BUS_DMA_NOWAIT, &vq->vq_dmamap);
	if (error) {
		return error;
	}*/

	if (bus_dmamem_alloc(vq->vq_dmat, (void **)&vq->vq_vaddr,
			BUS_DMA_NOWAIT,&vq->vq_dmamap)) {
		kprintf("bus_dmammem_load bad");
		return(ENOMEM);
	}

	if (bus_dmamap_load(vq->vq_dmat, vq->vq_dmamap, vq->vq_vaddr,
	            allocsize, virtio_helper, vq, BUS_DMA_NOWAIT) != 0){
		kprintf("bus_dmamap_load bad");
	}

	/* set the vq address */
	bus_space_write_4(sc->sc_iot,
			sc->sc_ioh,
			  VIRTIO_CONFIG_QUEUE_ADDRESS,
			  //(vq->vq_dmamap->dm_segs[0].ds_addr / VIRTIO_PAGE_SIZE));
			  (vq->bus_addr / VIRTIO_PAGE_SIZE));
	//kprintf("bus_addr is %u\n",vq->bus_addr);

	/* remember addresses and offsets for later use */
	vq->vq_owner = sc;
	vq->vq_num = vq_size;
	vq->vq_index = index;
	vq->vq_desc = vq->vq_vaddr;
	vq->vq_availoffset = sizeof(struct vring_desc)*vq_size;
	vq->vq_avail = (void*)(((char*)vq->vq_desc) + vq->vq_availoffset);
	vq->vq_usedoffset = allocsize1;
	vq->vq_used = (void*)(((char*)vq->vq_desc) + vq->vq_usedoffset);
	if (allocsize3 > 0) {
		vq->vq_indirectoffset = allocsize1 + allocsize2;
		vq->vq_indirect = (void*)(((char*)vq->vq_desc)
					  + vq->vq_indirectoffset);
	}
	vq->vq_bytesize = allocsize;
	vq->vq_maxsegsize = maxsegsize;
	vq->vq_maxnsegs = maxnsegs;

	/* free slot management */
	vq->vq_entries = kmalloc(sizeof(struct vq_entry)*vq_size, M_DEVBUF,
				     M_NOWAIT);
	if (vq->vq_entries == NULL) {
		r = ENOMEM;
		goto err;
	}

	virtio_init_vq(sc, vq);

	kprintf("allocated %u byte for virtqueue %d for %s, "
			   "size %d\n", allocsize, index, name, vq_size);
	if (allocsize3 > 0)
		kprintf( "using %d byte (%d entries) "
				   "indirect descriptors\n",
				   allocsize3, maxnsegs * vq_size);
	return 0;

err:
#if 0
	bus_space_write_4(sc->sc_iot, sc->sc_ioh,
			  VIRTIO_CONFIG_QUEUE_ADDRESS, 0);
	if (vq->vq_dmamap)
		bus_dmamap_destroy(sc->sc_dmat, vq->vq_dmamap);
	if (vq->vq_vaddr)
		bus_dmamem_unmap(sc->sc_dmat, vq->vq_vaddr, allocsize);
	if (vq->vq_segs[0].ds_addr)
		bus_dmamem_free(sc->sc_dmat, &vq->vq_segs[0], 1);
	memset(vq, 0, sizeof(*vq));

#endif
	return -1;
}

uint8_t
virtio_read_device_config_1(struct virtio_softc *sc, int index)
{
    return bus_space_read_1(sc->sc_iot, sc->sc_ioh,
                sc->sc_config_offset + index);
}
uint16_t
virtio_read_device_config_2(struct virtio_softc *sc, int index)
{
	return bus_space_read_2(sc->sc_iot, sc->sc_ioh,
				sc->sc_config_offset + index);
}
uint32_t
virtio_read_device_config_4(struct virtio_softc *sc, int index)
{
	return bus_space_read_4(sc->sc_iot, sc->sc_ioh,
				sc->sc_config_offset + index);
}
uint64_t
virtio_read_device_config_8(struct virtio_softc *sc, int index)
{
	uint64_t r;

	r = bus_space_read_4(sc->sc_iot, sc->sc_ioh,
			     sc->sc_config_offset + index + sizeof(uint32_t));
	r <<= 32;
	r += bus_space_read_4(sc->sc_iot, sc->sc_ioh,
			      sc->sc_config_offset + index);
	return r;
}
static inline void
vq_sync_indirect(struct virtio_softc *sc, struct virtqueue *vq, int slot,
		     int ops)
{
	//int offset = vq->vq_indirectoffset + sizeof(struct vring_desc) * vq->vq_maxnsegs * slot;

	bus_dmamap_sync(sc->requests_dmat, vq->vq_dmamap,
			//offset, sizeof(struct vring_desc) * vq->vq_maxnsegs,
			ops);
}
/*
 * dmamap sync operations for a virtqueue.
 */
static inline void
vq_sync_descs(struct virtio_softc *sc, struct virtqueue *vq, int ops)
{
	/* availoffset == sizeof(vring_desc)*vq_num */
	bus_dmamap_sync(sc->requests_dmat, vq->vq_dmamap, 
				//	0, vq->vq_availoffset,
			ops);
}
static void
vq_free_entry(struct virtqueue *vq, struct vq_entry *qe)
{
	spin_lock(&vq->vq_freelist_lock);
	TAILQ_INSERT_TAIL(&vq->vq_freelist, qe, qe_list);
	spin_unlock(&vq->vq_freelist_lock);

	return;
}


/*
 * enqueue_commit: add it to the aring.
 */
int
virtio_enqueue_commit(struct virtio_softc *sc, struct virtqueue *vq, int slot,
		      bool notifynow)
{
	struct vq_entry *qe1;

	if (slot < 0) {
		spin_lock(&vq->vq_aring_lock);
		goto notify;
	}
	vq_sync_descs(sc, vq, BUS_DMASYNC_PREWRITE);
	qe1 = &vq->vq_entries[slot];
	if (qe1->qe_indirect)
		vq_sync_indirect(sc, vq, slot, BUS_DMASYNC_PREWRITE);
	spin_lock(&vq->vq_aring_lock);
	vq->vq_avail->ring[(vq->vq_avail_idx++) % vq->vq_num] = slot;

	notify:
	if (notifynow) {
		vq_sync_aring(sc, vq, BUS_DMASYNC_PREWRITE);
		vq_sync_uring(sc, vq, BUS_DMASYNC_PREREAD);

	
		bus_space_barrier(sc->sc_iot, sc->sc_ioh, vq->vq_avail->idx, 2,
						  BUS_SPACE_BARRIER_WRITE);
		
		vq->vq_avail->idx = vq->vq_avail_idx;
	
		vq_sync_aring(sc, vq, BUS_DMASYNC_PREWRITE);    


		bus_space_barrier(sc->sc_iot, sc->sc_ioh, vq->vq_queued, 4,
						  BUS_SPACE_BARRIER_WRITE);
		vq->vq_queued++;
	
		vq_sync_uring(sc, vq, BUS_DMASYNC_POSTREAD);

		bus_space_barrier(sc->sc_iot, sc->sc_ioh, vq->vq_used->flags, 2,
						  BUS_SPACE_BARRIER_READ);
		if (!(vq->vq_used->flags & VRING_USED_F_NO_NOTIFY)){
			
			bus_space_write_2(sc->sc_iot, sc->sc_ioh,
					  VIRTIO_CONFIG_QUEUE_NOTIFY,
					  vq->vq_index);
		}
	}
	spin_unlock(&vq->vq_aring_lock);

	return 0;
}

/* Free descriptor management.
 */
static struct vq_entry *
vq_alloc_entry(struct virtqueue *vq)
{
	struct vq_entry *qe;

	//mutex_enter(&vq->vq_freelist_lock);
	if (TAILQ_EMPTY(&vq->vq_freelist)) {
		//mutex_exit(&vq->vq_freelist_lock);
		return NULL;
	}
	qe = TAILQ_FIRST(&vq->vq_freelist);
	TAILQ_REMOVE(&vq->vq_freelist, qe, qe_list);
	//mutex_exit(&vq->vq_freelist_lock);

	return qe;
}

/*
 * enqueue_reserve: allocate remaining slots and build the descriptor chain.
 */
int
virtio_enqueue_reserve(struct virtio_softc *sc, struct virtqueue *vq,
		       int slot, int nsegs)
{
	int indirect;
	struct vq_entry *qe1 = &vq->vq_entries[slot];

	kassert(qe1->qe_next == -1);
	kassert(1 <= nsegs && nsegs <= vq->vq_num);

	if ((vq->vq_indirect != NULL) &&
	    (nsegs >= MINSEG_INDIRECT) &&
	    (nsegs <= vq->vq_maxnsegs))
		indirect = 1;
	else
		indirect = 0;
	qe1->qe_indirect = indirect;

	if (indirect) {
		struct vring_desc *vd;
		int i;

		vd = &vq->vq_desc[qe1->qe_index];
		//vd->addr = vq->vq_dmamap->dm_segs[0].ds_addr
		vd->addr = vq->bus_addr
			+ vq->vq_indirectoffset;
		vd->addr += sizeof(struct vring_desc)
			* vq->vq_maxnsegs * qe1->qe_index;
		vd->len = sizeof(struct vring_desc) * nsegs;
		vd->flags = VRING_DESC_F_INDIRECT;

		vd = vq->vq_indirect;
		vd += vq->vq_maxnsegs * qe1->qe_index;
		qe1->qe_desc_base = vd;

		for (i = 0; i < nsegs-1; i++) {
			vd[i].flags = VRING_DESC_F_NEXT;
		}
		vd[i].flags = 0;
		qe1->qe_next = 0;

		return 0;
	} else {
		struct vring_desc *vd;
		struct vq_entry *qe;
		int i, s;

		vd = &vq->vq_desc[0];
		qe1->qe_desc_base = vd;
		qe1->qe_next = qe1->qe_index;
		s = slot;
		for (i = 0; i < nsegs - 1; i++) {
			qe = vq_alloc_entry(vq);
			if (qe == NULL) {
				vd[s].flags = 0;
				//virtio_enqueue_abort(sc, vq, slot);
				return EAGAIN;
			}
			vd[s].flags = VRING_DESC_F_NEXT;
			vd[s].next = qe->qe_index;
			s = qe->qe_index;
		}
		vd[s].flags = 0;

		return 0;
	}
}

int
virtio_enqueue_p(struct virtio_softc *sc, struct virtqueue *vq, int slot, 
				 bus_addr_t	ds_addr, bus_size_t	ds_len,		
				 bus_dmamap_t dmamap, bus_addr_t start, bus_size_t len,	
				 bool write)
{
	struct vq_entry *qe1 = &vq->vq_entries[slot];
	struct vring_desc *vd = qe1->qe_desc_base;
	int s = qe1->qe_next;

	kassert(s >= 0);
//	kassert(dmap->dm_nsegs == 1); /* XXX */
	debug("ds_len:%lu, start:%lu, len:%lu\n", ds_len, start, len);
	kassert((ds_len > start) &&	(ds_len >= start + len));

	vd[s].addr = ds_addr + start;
	vd[s].len = len;
	if (!write)
		vd[s].flags |= VRING_DESC_F_WRITE;
	qe1->qe_next = vd[s].next;

	return 0;
}

/*
 * enqueue: enqueue a single dmamap.
 */
int
virtio_enqueue(struct virtio_softc *sc, struct virtqueue *vq, int slot, 
			   bus_dma_segment_t *segs, int nseg,
			   bus_dmamap_t dmamap, 
			   bool write)
{
	struct vq_entry *qe1 = &vq->vq_entries[slot];
	struct vring_desc *vd = qe1->qe_desc_base;
	int i;
	int s = qe1->qe_next;

	kassert(s >= 0);
	//kassert(dmamap->dm_nsegs > 0);
	for (i = 0; i < nseg; i++) {
		vd[s].addr = segs[i].ds_addr;
		vd[s].len = segs[i].ds_len;
		if (!write)
			vd[s].flags |= VRING_DESC_F_WRITE;
		debug("s:%d addr:0x%llu len:%lu\n", s,
			(unsigned long long)vd[s].addr,(unsigned long) vd[s].len);
		s = vd[s].next;
	}
	
	qe1->qe_next = s;

	return 0;
}

/*
 * enqueue_prep: allocate a slot number
 */
int
virtio_enqueue_prep(struct virtio_softc *sc, struct virtqueue *vq, int *slotp)
{
	struct vq_entry *qe1;

	kassert(slotp != NULL);

	qe1 = vq_alloc_entry(vq);
	if (qe1 == NULL)
		return EAGAIN;
	/* next slot is not allocated yet */
	qe1->qe_next = -1;
	*slotp = qe1->qe_index;

	return 0;
}


/*
 * Can be used as sc_intrhand.
 */
/*
 * Scan vq, bus_dmamap_sync for the vqs (not for the payload),
 * and calls (*vq_done)() if some entries are consumed.
 */
int
virtio_vq_intr(struct virtio_softc *sc)
{
	struct virtqueue *vq;
	int i, r = 0;

	for (i = 0; i < sc->sc_nvqs; i++) {
		vq = &sc->sc_vqs[i];
		if (vq->vq_queued) {
			vq->vq_queued = 0;
			vq_sync_aring(sc, vq, BUS_DMASYNC_POSTWRITE);
		}
		vq_sync_uring(sc, vq, BUS_DMASYNC_POSTREAD);
		bus_space_barrier(sc->sc_iot, sc->sc_ioh, vq->vq_used_idx, 2,
						  BUS_SPACE_BARRIER_READ);
		//membar_consumer();
		if (vq->vq_used_idx != vq->vq_used->idx) {
			if (vq->vq_done)
				r |= (vq->vq_done)(vq);
		}
	}
		

	return r;
}
/*
 * Dequeue a request.
 */
/*
 * dequeue: dequeue a request from uring; dmamap_sync for uring is
 *	    already done in the interrupt handler.
 */
int
virtio_dequeue(struct virtio_softc *sc, struct virtqueue *vq,
	       int *slotp, int *lenp)
{
	uint16_t slot, usedidx;
	struct vq_entry *qe;

	if (vq->vq_used_idx == vq->vq_used->idx)
		return ENOENT;
	spin_lock(&vq->vq_uring_lock);
	usedidx = vq->vq_used_idx++;
	spin_unlock(&vq->vq_uring_lock);
	usedidx %= vq->vq_num;
	slot = vq->vq_used->ring[usedidx].id;
	qe = &vq->vq_entries[slot];

	if (qe->qe_indirect)
		vq_sync_indirect(sc, vq, slot, BUS_DMASYNC_POSTWRITE);

	if (slotp)
		*slotp = slot;
	if (lenp)
		*lenp = vq->vq_used->ring[usedidx].len;

	return 0;
}
/*
 * dequeue_commit: complete dequeue; the slot is recycled for future use.
 *                 if you forget to call this the slot will be leaked.
 */
int
virtio_dequeue_commit(struct virtio_softc *sc, struct virtqueue *vq, int slot)
{
	struct vq_entry *qe = &vq->vq_entries[slot];
	struct vring_desc *vd = &vq->vq_desc[0];
	int s = slot;

	while (vd[s].flags & VRING_DESC_F_NEXT) {
		kprintf("vringdescnext\n");
		s = vd[s].next;
		vq_free_entry(vq, qe);
		qe = &vq->vq_entries[s];
	}
	vq_free_entry(vq, qe);

	return 0;
}
/*
 * Feature negotiation.
 */
uint32_t
virtio_negotiate_features(struct virtio_softc *sc, uint32_t guest_features)
{

    uint32_t r;

	/* 
	* XXX- this is true with ld_virtio.c in nbsd on kvm... so set it until
	* we know what it really does...
	*/ 
	#if 0  
    if (!(device_cfdata(sc->dev)->cf_flags & 1) && !(device_cfdata(sc->sc_child)->cf_flags & 1)) {
		guest_features |= VIRTIO_F_RING_INDIRECT_DESC;
    }
	#endif 
	guest_features |= VIRTIO_F_RING_INDIRECT_DESC;

    r = bus_space_read_4(sc->sc_iot, sc->sc_ioh,
            VIRTIO_CONFIG_DEVICE_FEATURES);
    r &= guest_features;
    bus_space_write_4(sc->sc_iot, sc->sc_ioh,
            VIRTIO_CONFIG_GUEST_FEATURES, r);
    sc->sc_features = r;
    if (r & VIRTIO_F_RING_INDIRECT_DESC){
        sc->sc_indirect = true;
    }
    else{
        sc->sc_indirect = false;
    }

//virtio_negotiate_features: indirect false
                               return r;

}


static int virtio_probe(device_t dev)
{
	u_int32_t id = pci_get_device(dev);
	kprintf("%s %d",__FUNCTION__,id);
	if (id >= 0x1000  && id <= 0x103f){
		//debug
		kprintf("Device id %d is accepted", id); 

		return 0;
	}
	
	return 1;
}

static int virtio_detach(device_t dev)
{	
	
	struct virtio_softc *sc = device_get_softc(dev);
	debug("");


	/*destroy parent DMA tag*/
	if (sc->virtio_dmat) 
		bus_dma_tag_destroy(sc->virtio_dmat);
	
    /* disconnect the interrupt handler */
	if (sc->virtio_intr)
		bus_teardown_intr(sc->dev, sc->res_irq, sc->virtio_intr);
	if (sc->res_irq != NULL)
		bus_release_resource(sc->dev, SYS_RES_IRQ, 0, sc->res_irq);

    /* release the register window mapping */
	if (sc->io!= NULL)
		bus_release_resource(sc->dev, SYS_RES_IOPORT, PCIR_MAPS, sc->io);
   
	if (sc->sc_child) {
		debug("Deleting child\n");
		if(device_delete_child(sc->dev, sc->sc_child)!=0)
			debug("Couldn't delete child device\n");
		
	}
	return 0;
}

static int
virtio_intr(void *arg)
{

	struct virtio_softc *sc = arg;
	int isr, r = 0;

	/* check and ack the interrupt */
	isr = bus_space_read_1(sc->sc_iot, sc->sc_ioh,
						   VIRTIO_CONFIG_ISR_STATUS);

	if (isr == 0)
		return 0;
	if ((isr & VIRTIO_CONFIG_ISR_CONFIG_CHANGE) &&
		(sc->sc_config_change != NULL)){
		kprintf("config change\n");
		r = (sc->sc_config_change)(sc);
	}

	if (sc->sc_intrhand != NULL){
		r |= (sc->sc_intrhand)(sc);
	}
	
	return r;
};

static int virtio_attach(device_t dev)
{
    //debug
	kprintf("We enter virtio_attach");

	//struct virtio_softc *

	/*!
	 * void * device_get_softc(device_t dev);
     * Return the driver-specific state of dev.  The softc is automatically
     * allocated the first time it is requested.
     *
     * The pointer to the driver-specific instance variable is returned.
     *
	 */

	sc = device_get_softc(dev);
	int rid, error;
	device_t child;
	sc->dev = dev;
	int virtio_type;

	/*? PCI_MAPS */

	rid = PCIR_BAR(0);

	/*!
	 * struct resource *
     * bus_alloc_resource(device_t dev, int type, int *rid, u_long start,
	 * u_long end, u_long count, u_int flags);
	 */
    sc->io = bus_alloc_resource(dev, SYS_RES_IOPORT, &rid,
            0, ~0, 1, RF_ACTIVE);
    if (!sc->io) {
        device_printf(dev, "No I/O space?!\n");
        return ENOMEM;
    }

	sc->sc_iot = rman_get_bustag(sc->io);
    sc->sc_ioh = rman_get_bushandle(sc->io);
    sc->sc_config_offset = VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI;
	sc->sc_config_change = 0;
	sc->sc_intrhand = virtio_vq_intr;
	
	virtio_type = pci_read_config(dev, PCIR_SUBDEV_0, 2);
    kprintf("Virtio %s Device (rev. 0x%02x) %p\n",
            (virtio_type<NDEVNAMES?
             virtio_device_name[virtio_type]:"Unknown"),
            pci_read_config(dev, PCIR_REVID, 1),dev);

	sc->res_irq = bus_alloc_resource_any(sc->dev, SYS_RES_IRQ,
            &sc->rid_irq, RF_SHAREABLE|RF_ACTIVE);
    if (sc->res_irq == NULL){
        kprintf("Couldn't alloc res_irq\n");
    }

	error = bus_setup_intr(sc->dev, sc->res_irq, 0,
			(driver_intr_t *)virtio_intr, (void *)sc,
			&(sc->virtio_intr), NULL);

	if (error){
		kprintf("Couldn't setup intr\n");
		return(1);
	}

	virtio_device_reset(sc);
	virtio_set_status(sc, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	virtio_set_status(sc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);

	if (bus_dma_tag_create(NULL,
			1,
			0,
			BUS_SPACE_MAXADDR,
			BUS_SPACE_MAXADDR,
			NULL, NULL,
	        BUS_SPACE_MAXSIZE_32BIT,
			0,
	        BUS_SPACE_MAXSIZE_32BIT,
			0,
			&sc->virtio_dmat)!=0){
		goto handle_error;

	}
	sc->sc_childdevid = virtio_type;
	kprintf("Virtio Type: %d\n", virtio_type);
	if (virtio_type == PCI_PRODUCT_VIRTIO_NETWORK) {
			sc->sc_child = child = device_add_child(dev, "virtio-net",0);
			kprintf("Network dev child added \n");
	}
	else if (virtio_type == PCI_PRODUCT_VIRTIO_BLOCK) {
			child = device_add_child(dev, "virtio_blk",0);
	} 
	else {
		kprintf("Dev %s not supported\n",virtio_device_name[virtio_type]); 
		goto handle_error;
	}
	return 0;

handle_error:
	if (sc->io) {
		bus_release_resource(dev, SYS_RES_IOPORT, PCIR_BAR(0), sc->io);
	}
	if (sc->res_irq) {
		bus_release_resource(dev, SYS_RES_IRQ, 0, sc->res_irq);
	}
	return 1;
}
static device_method_t virtio_methods[] = {
	DEVMETHOD(device_probe,         virtio_probe),
	DEVMETHOD(device_attach,        virtio_attach),
	DEVMETHOD(device_detach,        virtio_detach),
	{ 0, 0 }
};

static driver_t virtio_driver = {
	"virtiobus",
	virtio_methods,
	sizeof(struct virtio_softc),
};

static devclass_t virtio_devclass;

DRIVER_MODULE(virtiobus, pci, virtio_driver, virtio_devclass, 0, 0);
MODULE_VERSION(virtiobus, 0);
