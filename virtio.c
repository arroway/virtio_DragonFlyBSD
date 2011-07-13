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
 *
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
	"Unknown (0)",	/* 0 */
	"Network",	/* 1 */
	"Block",	/* 2 */
	"Console",	/* 3 */
	"Entropy",	/* 4 */
	"Memory Balloon",	/* 5 */
	"Unknown (6)",	/* 6 */
	"Unknown (7)",	/* 7 */
	"Unknown (8)",	/* 8 */
	"9P Transport"	/* 9 */ 
};

#define NDEVNAMES	(sizeof(virtio_device_name)/sizeof(char*))
#define MINSEG_INDIRECT	2	/* use indirect if nsegs >= this value */
#define VIRTQUEUE_ALIGN(n)	(((n)+(VIRTIO_PAGE_SIZE-1))& \
				 ~(VIRTIO_PAGE_SIZE-1))
#define virtio_device_reset(sc)	virtio_set_status((sc), 0)

/*
 * Declarations
 */
static inline void      vq_sync_uring(struct virtio_softc *sc,
				      struct virtqueue *vq, int ops);
static inline void      vq_sync_aring(struct virtio_softc *sc,
				      struct virtqueue *vq, int ops);
static void             virtio_init_vq(struct virtio_softc *sc,
				       struct virtqueue *vq);
static void             virtio_helper(void *arg, bus_dma_segment_t *segs,
				      int nseg, int error);
static inline void      vq_sync_indirect(struct virtio_softc *sc,
					 struct virtqueue *vq, int slot, int ops);
static inline void      vq_sync_descs(struct virtio_softc *sc,
				      struct virtqueue *vq, int ops);
static void             vq_free_entry(struct virtqueue *vq,
				      struct vq_entry *qe);
static struct vq_entry *        vq_alloc_entry(struct virtqueue *vq); 
static int              virtio_probe(device_t dev);
static int              virtio_detach(device_t dev);
static int              virtio_intr(void *arg);
static int              virtio_attach(device_t dev);


void virtio_set_status(struct virtio_softc *sc, int status)
{
	int old = 0;

	if (status != 0)
		old = bus_space_read_1(sc->sc_iot, sc->sc_ioh,
				       VIRTIO_CONFIG_DEVICE_STATUS);

	bus_space_write_1(sc->sc_iot, sc->sc_ioh, VIRTIO_CONFIG_DEVICE_STATUS,
			  status|old);
}

/*
 * Reset the device:
 * To reset the device to a known state, do following:
 *	virtio_reset(sc); this will stop the device activity
 *	<dequeue finished requests>;  virtio_dequeue() still can be called
 *	<revoke pending requests in the vqs if any>;
 *	virtio_reinit_begin(sc);      dequeue prohibitted
 *	newfeatures = virtio_negotiate_features(sc, requestedfeatures);
 *	<some other initialization>;
 *	virtio_reinit_end(sc);	      device activated; enqueue allowed
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
	bus_dmamap_sync(sc->requests_dmat, vq->vq_dmamap, ops);
}

static inline void
vq_sync_aring(struct virtio_softc *sc, struct virtqueue *vq, int ops)
{
	bus_dmamap_sync(sc->requests_dmat, vq->vq_dmamap, ops);
}


void
virtio_reinit_start(struct virtio_softc *sc)
{
	int i;

	virtio_set_status(sc, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	virtio_set_status(sc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);
	for (i = 0; i < sc->sc_nvqs; i++) {
		int n;
		struct virtqueue *vq = &sc->sc_vqs[i];
		bus_space_write_2(sc->sc_iot, sc->sc_ioh,
				  VIRTIO_CONFIG_QUEUE_SELECT,
				  vq->vq_index);
		n = bus_space_read_2(sc->sc_iot, sc->sc_ioh,
				     VIRTIO_CONFIG_QUEUE_SIZE);
		if (n == 0)	/* vq disappeared */
			continue;
		if (n != vq->vq_num) {
			debug("virtqueue size changed, vq index %d\n",
			      vq->vq_index);
		}
		virtio_init_vq(sc, vq);
		bus_space_write_4(sc->sc_iot, sc->sc_ioh,
				  VIRTIO_CONFIG_QUEUE_ADDRESS,
				  (vq->bus_addr
				   / VIRTIO_PAGE_SIZE));
	}
}

void
virtio_reinit_end(struct virtio_softc *sc)
{
	virtio_set_status(sc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);
}




/*
 * Start/stop vq interrupt.  No guarantee.
 */
void
virtio_stop_vq_intr(struct virtio_softc *sc, struct virtqueue *vq)
{
	vq->vq_avail->flags |= VRING_AVAIL_F_NO_INTERRUPT;
	vq_sync_aring(sc, vq, BUS_DMASYNC_PREWRITE);
	vq->vq_queued++;
}

void
virtio_start_vq_intr(struct virtio_softc *sc, struct virtqueue *vq)
{
	vq->vq_avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;
	vq_sync_aring(sc, vq, BUS_DMASYNC_PREWRITE);
	vq->vq_queued++;
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
		/*foo*/
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
		TAILQ_INSERT_TAIL(&vq->vq_freelist, &vq->vq_entries[i],
				  qe_list); 
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

	/*
	 * device must be already deactivated
	 * confirm the vq is empty
	 */ 

	TAILQ_FOREACH(qe, &vq->vq_freelist, qe_list) {
		i++;
	}

	if (i != vq->vq_num) {
		kprintf("%s: freeing non-empty vq, index %d\n", __func__,
			vq->vq_index);
		return EBUSY;
	}

	/* tell device that there's no virtqueue any longer */
	bus_space_write_2(sc->sc_iot, sc->sc_ioh, VIRTIO_CONFIG_QUEUE_SELECT,
			  vq->vq_index);
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, VIRTIO_CONFIG_QUEUE_ADDRESS, 0); 
	kfree(vq->vq_entries, M_DEVBUF);
	spin_uninit(&vq->vq_freelist_lock);
	spin_uninit(&vq->vq_uring_lock);
	spin_uninit(&vq->vq_aring_lock);

	return 0;
}

int
virtio_alloc_vq(struct virtio_softc *sc, struct virtqueue *vq, int index,
		int maxsegsize, int maxnsegs, const char *name)
{
	int vq_size, allocsize1, allocsize2, allocsize3, allocsize = 0;
	int  r;
	int error;
	debug("ind:%d, %d %d\n",index,(unsigned int)sc->sc_iot,
	      (unsigned int)sc->sc_ioh);
	memset(vq, 0, sizeof(*vq));

	bus_space_write_2(sc->sc_iot, sc->sc_ioh, VIRTIO_CONFIG_QUEUE_SELECT,
			  index);

	vq_size = bus_space_read_2(sc->sc_iot, sc->sc_ioh, 
				   VIRTIO_CONFIG_QUEUE_SIZE);
	if (vq_size == 0) {
		panic( "virtqueue not exist, index %d for %s\n", index, name);
	}

	/* allocsize1: descriptor table + avail ring + pad */
	allocsize1 = VIRTQUEUE_ALIGN(sizeof(struct vring_desc)*vq_size + 
				     sizeof(uint16_t)*(2+vq_size));

	/* allocsize2: used ring + pad */
	allocsize2 = VIRTQUEUE_ALIGN(sizeof(uint16_t)*2 + 
				     sizeof(struct vring_used_elem)*vq_size);

	/* allocsize3: indirect table */
	if (sc->sc_indirect && maxnsegs >= MINSEG_INDIRECT)
		allocsize3 = sizeof(struct vring_desc) * maxnsegs * vq_size;
	else
		allocsize3 = 0;

	allocsize = allocsize1 + allocsize2 + allocsize3;
	debug("a1:%d a2:%d a3:%d a4:%d\n", allocsize1, allocsize2, allocsize3, 
	      allocsize);

	if (sc->virtio_dmat== NULL) {
		kprintf("dmat is null\n");
		return 1;
	}

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


	if (bus_dmamem_alloc(vq->vq_dmat, (void **)&vq->vq_vaddr, 
			     BUS_DMA_NOWAIT,&vq->vq_dmamap)) {
		kprintf("bus_dmammem_load bad");
		return(ENOMEM);
	}

	if (bus_dmamap_load(vq->vq_dmat, vq->vq_dmamap, vq->vq_vaddr, allocsize,
			    virtio_helper, vq, BUS_DMA_NOWAIT) != 0) {
		kprintf("bus_dmamap_load bad");
	}

	/* set the vq address */
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, VIRTIO_CONFIG_QUEUE_ADDRESS,
			  (vq->bus_addr / VIRTIO_PAGE_SIZE));

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
		vq->vq_indirect = (void*)(((char*)vq->vq_desc) + 
					  vq->vq_indirectoffset);
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

	kprintf("allocated %u byte for virtqueue %d for %s, size %d\n", 
		allocsize, index, name, vq_size);
	if (allocsize3 > 0) {
		kprintf( "using %d byte (%d entries) indirect descriptors\n",
			 allocsize3, maxnsegs * vq_size);
	}
	return 0;


err:
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, VIRTIO_CONFIG_QUEUE_ADDRESS, 0);
	if (vq->vq_entries) {
		kfree(vq->vq_entries,M_DEVBUF);
	}
	bus_dmamap_unload(vq->vq_dmat, vq->vq_dmamap);
	bus_dmamem_free(vq->vq_dmat, vq->vq_vaddr, vq->vq_dmamap);
	bus_dma_tag_destroy(vq->vq_dmat);
	memset(vq, 0, sizeof(*vq));

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
	bus_dmamap_sync(sc->requests_dmat, vq->vq_dmamap, ops);
}

/*
 * dmamap sync operations for a virtqueue.
 */
static inline void
vq_sync_descs(struct virtio_softc *sc, struct virtqueue *vq, int ops)
{
	bus_dmamap_sync(sc->requests_dmat, vq->vq_dmamap, ops);
}

static void
vq_free_entry(struct virtqueue *vq, struct vq_entry *qe)
{
	kprintf("call of q_free_entry(): vq_num=%u", vq->vq_num);
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

	debug("Enter virtio_enqueue_commit\n");

	if (slot < 0) {
		spin_lock(&vq->vq_aring_lock);
		debug("spin_lock\n");
		goto notify;
	}
	debug("before vq_sync_desc");
	vq_sync_descs(sc, vq, BUS_DMASYNC_PREWRITE);
	debug("vq_sync_desc");

	qe1 = &vq->vq_entries[slot];
	if (qe1->qe_indirect){
		debug("inside if vq_entries");
		vq_sync_indirect(sc, vq, slot, BUS_DMASYNC_PREWRITE);
		debug("after vq_sync_indirect");
	}

	spin_lock(&vq->vq_aring_lock);
	debug("spin_lock");
	vq->vq_avail->ring[(vq->vq_avail_idx++) % vq->vq_num] = slot;
	debug("affectation");

notify:
	debug("notify?\n");
	if (notifynow) {
		debug("in notify\n");
		vq_sync_aring(sc, vq, BUS_DMASYNC_PREWRITE);
		debug("after vq_sync_aring\n");
		vq_sync_uring(sc, vq, BUS_DMASYNC_PREREAD);
		debug("after vq_sync_uring");


		bus_space_barrier(sc->sc_iot, sc->sc_ioh, vq->vq_avail->idx, 2,
				BUS_SPACE_BARRIER_WRITE);
		debug("bus_space_barrier\n");

		vq->vq_avail->idx = vq->vq_avail_idx;
		debug("after affectation\n");

		vq_sync_aring(sc, vq, BUS_DMASYNC_PREWRITE);    
		debug("after vq_sync_aring\n");


		bus_space_barrier(sc->sc_iot, sc->sc_ioh, vq->vq_queued, 4,
				  BUS_SPACE_BARRIER_WRITE);
		debug("bus_space_barrier write\n");


		vq->vq_queued++;
		debug("incr vq_queued\n");

		vq_sync_uring(sc, vq, BUS_DMASYNC_POSTREAD);
		debug("after vq_sync_aring postread\n");


		bus_space_barrier(sc->sc_iot, sc->sc_ioh, vq->vq_used->flags, 2,
				  BUS_SPACE_BARRIER_READ);
		debug("after bus_space_barrier\n");


		if (!(vq->vq_used->flags & VRING_USED_F_NO_NOTIFY)) {

			debug("in if\n");

			bus_space_write_2(sc->sc_iot, sc->sc_ioh,
					  VIRTIO_CONFIG_QUEUE_NOTIFY,
					  vq->vq_index);

			debug("after bus_space_write\n");

		}
	}
	spin_unlock(&vq->vq_aring_lock);
	debug("end of virito_enqueue_commit\n");
	return 0;
}

/* 
 *  Free descriptor management.
 */
static struct vq_entry *
vq_alloc_entry(struct virtqueue *vq) {
	struct vq_entry *qe;

	spin_lock(&vq->vq_freelist_lock);
	if (TAILQ_EMPTY(&vq->vq_freelist)) {
		spin_unlock(&vq->vq_freelist_lock);
		return NULL; 
	}
	qe = TAILQ_FIRST(&vq->vq_freelist);
	TAILQ_REMOVE(&vq->vq_freelist, qe, qe_list);
	spin_unlock(&vq->vq_freelist_lock);

	return qe;
}

/*
 * enqueue_reserve: allocate remaining slots and build the descriptor chain.
 */
int
virtio_enqueue_reserve(struct virtio_softc *sc, struct virtqueue *vq, int slot,
		       int nsegs)
{
	int indirect;
	int i, s;
	struct vq_entry *qe1 = &vq->vq_entries[slot];
	struct vq_entry *qe;
	struct vring_desc *vd;

	KKASSERT(qe1->qe_next == -1);
	KKASSERT(1 <= nsegs && nsegs <= vq->vq_num);

	if ((vq->vq_indirect != NULL) &&
	    (nsegs >= MINSEG_INDIRECT) &&
	    (nsegs <= vq->vq_maxnsegs))
		indirect = 1;
	else
		indirect = 0;
	qe1->qe_indirect = indirect;

	if (indirect) {

		vd = &vq->vq_desc[qe1->qe_index];
		vd->addr = vq->bus_addr + vq->vq_indirectoffset;
		vd->addr += sizeof(struct vring_desc) * vq->vq_maxnsegs *
			    qe1->qe_index;
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
		vd = &vq->vq_desc[0];
		qe1->qe_desc_base = vd;
		qe1->qe_next = qe1->qe_index;
		s = slot;
		for (i = 0; i < nsegs - 1; i++) {
			qe = vq_alloc_entry(vq);
			if (qe == NULL) {
				vd[s].flags = 0;
				kprintf("here\n");
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
		 bus_addr_t ds_addr, bus_size_t ds_len, bus_dmamap_t dmamap,
		 bus_addr_t start, bus_size_t len, bool write)
{
	struct vq_entry *qe1 = &vq->vq_entries[slot];
	struct vring_desc *vd = qe1->qe_desc_base;
	int s = qe1->qe_next;

	KKASSERT(s >= 0);
	debug("ds_len:%lu, start:%lu, len:%lu\n", ds_len, start, len);
	KKASSERT((ds_len > start) && (ds_len >= start + len));

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
	       bus_dma_segment_t *segs, int nseg, bus_dmamap_t dmamap, bool write)
{
	struct vq_entry *qe1 = &vq->vq_entries[slot];
	struct vring_desc *vd = qe1->qe_desc_base;
	int i;
	int s = qe1->qe_next;

	debug("enter virtio_enqueue");

	KKASSERT(s >= 0);
	debug("after KKASSERT");

	for (i = 0; i < nseg; i++) {
		debug("in for loop");

		debug("i = %d, addr :%08X", i, segs[i].ds_addr );
		debug("i = %d, len :%08X", i, segs[i].ds_len );

		vd[s].addr = segs[i].ds_addr;
		vd[s].len = segs[i].ds_len;

		if (!write)
			vd[s].flags |= VRING_DESC_F_WRITE;
		debug("s:%d addr:0x%llu len:%lu\n", s, 
		      (unsigned long long)vd[s].addr,(unsigned long) vd[s].len);
		s = vd[s].next;
		debug("i = %d, next :%08X", i, vd[s].next );
	}

	qe1->qe_next = s;
	debug("out of virtio_enqueue");

	return 0;
}

/*
 * enqueue_prep: allocate a slot number
 */
int
virtio_enqueue_prep(struct virtio_softc *sc, struct virtqueue *vq, int *slotp)
{
	struct vq_entry *qe1;

	KKASSERT(slotp != NULL);

	qe1 = vq_alloc_entry(vq);
	if (qe1 == NULL)
		return EAGAIN;
	/* next slot is not allocated yet */
	qe1->qe_next = -1;
	*slotp = qe1->qe_index;

	return 0;
}

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
		if (vq->vq_used_idx != vq->vq_used->idx) {
			if (vq->vq_done)
				r |= (vq->vq_done)(vq);
		}
	}

	return r;
}


/*
 * enqueue_abort: rollback.
 */
int
virtio_enqueue_abort(struct virtio_softc *sc, struct virtqueue *vq, int slot)
{
	struct vq_entry *qe = &vq->vq_entries[slot];
	struct vring_desc *vd;
	int s;

	if (qe->qe_next < 0) {
		vq_free_entry(vq, qe);
		return 0;
	}

	s = slot;
	vd = &vq->vq_desc[0];
	while (vd[s].flags & VRING_DESC_F_NEXT) {
		s = vd[s].next;
		vq_free_entry(vq, qe);
		qe = &vq->vq_entries[s];
	}
	vq_free_entry(vq, qe);
	return 0;
}


/*
 * Dequeue a request: dequeue a request from uring; dmamap_sync for uring is 
 * already done in the interrupt handler.
 */
int
virtio_dequeue(struct virtio_softc *sc, struct virtqueue *vq, int *slotp,
	       int *lenp)
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
 * 	if you forget to call this the slot will be leaked.
 */
int
virtio_dequeue_commit(struct virtio_softc *sc, struct virtqueue *vq, int slot)
{
	struct vq_entry *qe = &vq->vq_entries[slot];
	struct vring_desc *vd = &vq->vq_desc[0];
	int s = slot;

	while (vd[s].flags & VRING_DESC_F_NEXT) {
		//kprintf("vringdescnext\n");
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

	guest_features |= VIRTIO_F_RING_INDIRECT_DESC;

	r = bus_space_read_4(sc->sc_iot, sc->sc_ioh, VIRTIO_CONFIG_DEVICE_FEATURES);
	r &= guest_features;
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, VIRTIO_CONFIG_GUEST_FEATURES, r);
	sc->sc_features = r;
	if (r & VIRTIO_F_RING_INDIRECT_DESC) {
		sc->sc_indirect = true;
	} else {
		sc->sc_indirect = false;
	}

	return r;

}


static int 
virtio_probe(device_t dev)
{
	uint32_t id = pci_get_device(dev);
	if (id >= 0x1000  && id <= 0x103f) {
		return 0;
	}

	return 1;
}

static int 
virtio_detach(device_t dev)
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
		if (device_delete_child(sc->dev, sc->sc_child)!=0)
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
	isr = bus_space_read_1(sc->sc_iot, sc->sc_ioh, VIRTIO_CONFIG_ISR_STATUS);

	if (isr == 0)
		return 0;
	if ((isr & VIRTIO_CONFIG_ISR_CONFIG_CHANGE) &&
	    (sc->sc_config_change != NULL)) {
		kprintf("config change\n");
		r = (sc->sc_config_change)(sc);
	}

	if (sc->sc_intrhand != NULL) {
		r |= (sc->sc_intrhand)(sc);
	}

	return r;
};

static int 
virtio_attach(device_t dev)
{
	struct virtio_softc *sc = device_get_softc(dev);
	int rid, error;
	device_t child;
	sc->dev = dev;
	int virtio_type;
	rid = PCIR_BAR(0);
	sc->io = bus_alloc_resource(dev, SYS_RES_IOPORT, &rid, 0, ~0, 1,
				    RF_ACTIVE);
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

	sc->res_irq = bus_alloc_resource_any(sc->dev, SYS_RES_IRQ, &sc->rid_irq,
					     RF_SHAREABLE|RF_ACTIVE);
	if (sc->res_irq == NULL) {
		kprintf("Couldn't alloc res_irq\n");
	}
	error = bus_setup_intr(sc->dev,
			       sc->res_irq,
			       0, 
			       (driver_intr_t *)virtio_intr,
			       (void *)sc,
			       &(sc->virtio_intr), 
			       NULL);

	if (error) {
		kprintf("Couldn't setup intr\n");
		return(1);
	}

	virtio_device_reset(sc);
	virtio_set_status(sc, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	virtio_set_status(sc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);

	error = bus_dma_tag_create(NULL, 1,
				   0,
				   BUS_SPACE_MAXADDR,
				   BUS_SPACE_MAXADDR,
				   NULL, NULL,
				   BUS_SPACE_MAXSIZE_32BIT,
				   0,
				   BUS_SPACE_MAXSIZE_32BIT,
				   0, &sc->virtio_dmat);
	if (error != 0) {
		goto handle_error;

	}

	if (virtio_type == PCI_PRODUCT_VIRTIO_NETWORK) {
		child = device_add_child(dev, "virtio_net",0);
	} else if (virtio_type == PCI_PRODUCT_VIRTIO_BLOCK) {
		child = device_add_child(dev, "virtio_blk",0);
	} else {
		kprintf("Dev %s not supported\n",
			virtio_device_name[virtio_type]); 
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
	{ 0, 0}
};

static driver_t virtio_driver = {
	"virtiobus",
	virtio_methods,
	sizeof(struct virtio_softc),
};

static devclass_t virtio_devclass;

DRIVER_MODULE(virtiobus, pci, virtio_driver, virtio_devclass, 0, 0);
MODULE_VERSION(virtiobus, 0);
