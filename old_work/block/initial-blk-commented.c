/*
 * cleaning some portions of the code that are already written in virtio.c
 * rajouter les commentaires dans virtio.c
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

#include <sys/disk.h>
#include <sys/buf.h>
#include <sys/devicestat.h>

#include <sys/spinlock.h>
#include <sys/spinlock2.h>

#include <bus/pci/pcivar.h>
#include <bus/pci/pcireg.h>

#include "blkvar.h"
/*!
#define kassert(exp) do { if (__predict_false(!(exp)))	\
					panic("assertion: %s in %s",	\
					#exp, __func__); } while (0)
*/

//already in virtio.c
//!static const char *virtio_device_name[] = {
//	"Unknown (0)",		/* 0 */
//	"Network",		/* 1 */
//	"Block",		/* 2 */
//	"Console",		/* 3 */
//	"Entropy",		/* 4 */
//	"Memory Balloon",	/* 5 */
//	"Unknown (6)",		/* 6 */
//	"Unknown (7)",		/* 7 */
//	"Unknown (8)",		/* 8 */
//	"9P Transport"		/* 9 */
//};


//!#define NDEVNAMES	(sizeof(virtio_device_name)/sizeof(char*))
//!#define MINSEG_INDIRECT     2 /* use indirect if nsegs >= this value */


static int  virtio_blk_probe(device_t dev);
static int  virtio_blk_attach(device_t dev);

/*! arleady in virtio.c
static uint8_t
virtio_read_device_config_1(struct virtio_blk_softc *sc, int index)
{
    return bus_space_read_1(sc->sc_iot, sc->sc_ioh,
                sc->sc_config_offset + index);
}
static uint16_t
virtio_read_device_config_2(struct virtio_blk_softc *sc, int index)
{
	return bus_space_read_2(sc->sc_iot, sc->sc_ioh,
				sc->sc_config_offset + index);
}
static uint32_t
virtio_read_device_config_4(struct virtio_blk_softc *sc, int index)
{
	return bus_space_read_4(sc->sc_iot, sc->sc_ioh,
				sc->sc_config_offset + index);
}

static uint64_t
virtio_read_device_config_8(struct virtio_blk_softc *sc, int index)
{
	uint64_t r;

	r = bus_space_read_4(sc->sc_iot, sc->sc_ioh,
			     sc->sc_config_offset + index + sizeof(uint32_t));
	r <<= 32;
	r += bus_space_read_4(sc->sc_iot, sc->sc_ioh,
			      sc->sc_config_offset + index);
	return r;
}

*/

/*
 * Interface to the device switch.
 */
static	d_open_t	vbd_disk_open;
static	d_close_t	vbd_disk_close;
static	d_strategy_t	vbd_disk_strategy;
static	d_dump_t	vbd_disk_dump;

static struct dev_ops vbd_disk_ops = {
	{ "vbd", 152/*AAC_DISK_CDEV_MAJOR*/, D_DISK},
	.d_open =      vbd_disk_open,
	.d_close =     vbd_disk_close,
	.d_read =      physread,
	.d_write =     physwrite,
	.d_strategy =      vbd_disk_strategy,
	.d_dump =      vbd_disk_dump,
} ;
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
 * Enqueue several dmamaps as a single request.
 */
/*
 * Typical usage:
 *  <queue size> number of followings are stored in arrays
 *  - command blocks (in dmamem) should be pre-allocated and mapped
 *  - dmamaps for command blocks should be pre-allocated and loaded
 *  - dmamaps for payload should be pre-allocated
 *      r = virtio_enqueue_prep(sc, vq, &slot);		// allocate a slot
 *	if (r)		// currently 0 or EAGAIN
 *	  return r;
 *	r = bus_dmamap_load(dmat, dmamap_payload[slot], data, count, ..);
 *	if (r) {
 *	  virtio_enqueue_abort(sc, vq, slot);
 *	  bus_dmamap_unload(dmat, dmamap_payload[slot]);
 *	  return r;
 *	}
 *	r = virtio_enqueue_reserve(sc, vq, slot, 
 *				   dmamap_payload[slot]->dm_nsegs+1);
 *							// ^ +1 for command
 *	if (r) {	// currently 0 or EAGAIN
 *	  bus_dmamap_unload(dmat, dmamap_payload[slot]);
 *	  return r;					// do not call abort()
 *	}
 *	<setup and prepare commands>
 *	bus_dmamap_sync(dmat, dmamap_cmd[slot],... BUS_DMASYNC_PREWRITE);
 *	bus_dmamap_sync(dmat, dmamap_payload[slot],...);
 *	virtio_enqueue(sc, vq, slot, dmamap_cmd[slot], false);
 *	virtio_enqueue(sc, vq, slot, dmamap_payload[slot], iswrite);
 *	virtio_enqueue_commit(sc, vq, slot, true);
 */

/*
 * enqueue_prep: allocate a slot number
 */

/*!
static int
virtio_enqueue_prep(struct virtio_blk_softc *sc, struct virtqueue *vq, int *slotp)
{
	struct vq_entry *qe1;

	kassert(slotp != NULL);

	qe1 = vq_alloc_entry(vq);
	if (qe1 == NULL)
		return EAGAIN;
	/* next slot is not allocated yet /
	qe1->qe_next = -1;
	*slotp = qe1->qe_index;

	return 0;
}
*/

/*
 * enqueue_reserve: allocate remaining slots and build the descriptor chain.
 */

/*!
static int
virtio_enqueue_reserve(struct virtio_blk_softc *sc, struct virtqueue *vq,
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
*/

/*!
static int
virtio_enqueue_p(struct virtio_blk_softc *sc, struct virtqueue *vq, int slot,
		 struct virtio_blk_req *vr, bus_dmamap_t dmamap, bus_addr_t start, bus_size_t len,
		 bool write)
{
	struct vq_entry *qe1 = &vq->vq_entries[slot];
	struct vring_desc *vd = qe1->qe_desc_base;
	int s = qe1->qe_next;

	kassert(s >= 0);
//	kassert(dmap->dm_nsegs == 1); /* XXX /
	kprintf("ds_len:%lu, start:%lu, len:%lu\n", vr->ds_len, start, len);
	kassert((vr->ds_len > start) &&	(vr->ds_len >= start + len));

	vd[s].addr = vr->ds_addr + start;
	vd[s].len = len;
	if (!write)
		vd[s].flags |= VRING_DESC_F_WRITE;
	qe1->qe_next = vd[s].next;

	return 0;
}

*/


static void
map_payload(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct virtio_blk_req *vr = (struct virtio_blk_req *) arg;
	vr->segs = segs;
	vr->nseg = nseg;
	kprintf("%s, %p:%p addr:%lu, len:%lu\n",
			__FUNCTION__,segs,vr->segs,vr->segs[0].ds_addr, vr->segs[0].ds_len);
}

/*
 * enqueue: enqueue a single dmamap.
 */

/*!
static int
virtio_enqueue(struct virtio_blk_softc *sc, struct virtqueue *vq, int slot, 
			   struct virtio_blk_req* vr,
	       bus_dmamap_t dmamap, bool write)
{
	struct vq_entry *qe1 = &vq->vq_entries[slot];
	struct vring_desc *vd = qe1->qe_desc_base;
	int i;
	int s = qe1->qe_next;

	kassert(s >= 0);
	//kassert(dmamap->dm_nsegs > 0);
	for (i = 0; i < vr->nseg; i++) {
		vd[s].addr = vr->segs[i].ds_addr;
		vd[s].len = vr->segs[i].ds_len;
		if (!write)
			vd[s].flags |= VRING_DESC_F_WRITE;
		kprintf("%s, s:%d addr:0x%llu len:%lu\n", __FUNCTION__, s,
			(unsigned long long)vd[s].addr,(unsigned long) vd[s].len);
		s = vd[s].next;
	}
	
/*if (!write)
		vd[s].flags |= VRING_DESC_F_WRITE;
	s = vd[s].next;
/
	qe1->qe_next = s;

	return 0;
}

*/

/*!
static inline void
vq_sync_indirect(struct virtio_blk_softc *sc, struct virtqueue *vq, int slot,
		     int ops)
{
	//int offset = vq->vq_indirectoffset + sizeof(struct vring_desc) * vq->vq_maxnsegs * slot;

	bus_dmamap_sync(sc->requests_dmat, vq->vq_dmamap,
			//offset, sizeof(struct vring_desc) * vq->vq_maxnsegs,
			ops);
}
*/
/*! already in virtio.c

static inline void
vq_sync_aring(struct virtio_blk_softc *sc, struct virtqueue *vq, int ops)
{
	bus_dmamap_sync(sc->requests_dmat, vq->vq_dmamap,
			//vq->vq_availoffset,
			//offsetof(struct vring_avail, ring)
			 //+ vq->vq_num * sizeof(uint16_t),
			ops);
}

static inline void
vq_sync_uring(struct virtio_blk_softc *sc, struct virtqueue *vq, int ops)
{
	bus_dmamap_sync(sc->requests_dmat, vq->vq_dmamap,
			//vq->vq_usedoffset,
			//offsetof(struct vring_used, ring)
			 //+ vq->vq_num * sizeof(struct vring_used_elem),
			ops);
}

!*/

/*
 * dmamap sync operations for a virtqueue.
 */

/*!
static inline void
vq_sync_descs(struct virtio_blk_softc *sc, struct virtqueue *vq, int ops)
{
	/* availoffset == sizeof(vring_desc)*vq_num /
	bus_dmamap_sync(sc->requests_dmat, vq->vq_dmamap, 
				//	0, vq->vq_availoffset,
			ops);
}

*/


/*
 * enqueue_commit: add it to the aring.
 */

/*!
static int
virtio_enqueue_commit(struct virtio_blk_softc *sc, struct virtqueue *vq, int slot,
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

*/

static int
blkvirtio_execute(struct virtio_blk_softc *sc, struct bio *bio)
{
	kprintf("%s %p\n", __FUNCTION__,(void *) bio);
	struct virtqueue *vq = &sc->sc_vq;
	struct buf *bp = bio->bio_buf;
	int isread = (bp->b_cmd & BUF_CMD_READ);
	int r;
	int slot;
	struct virtio_blk_req *vr;

	if (sc->sc_readonly && !isread){
		kprintf("is read only:%u but op is not\n", sc->sc_readonly);
		return EIO;
	}

	r = virtio_enqueue_prep(sc, vq, &slot);
	if (r != 0){
		kprintf("Bad bus_dmamap_load\n");
		return r;
	}
	kprintf("slot is %d\n", slot);

	vr = &sc->sc_reqs[slot];
	r = bus_dmamap_load(sc->payloads_dmat, 
						vr->payload_dmap,
						bp->b_data, 
						bp->b_bcount, 
						map_payload,
						vr, 
						0);
	if (r != 0){
		kprintf("Bad bus_dmamap_load\n");
		return r;
	}
	r = virtio_enqueue_reserve(sc, vq, slot, vr->nseg + 2);
	if (r != 0) {
		kprintf("Bad enqueue_reserve\n");
		return r;
 	}
 	vr->vr_bp = bp;
	vr->vr_hdr.type = isread?VIRTIO_BLK_T_IN:VIRTIO_BLK_T_OUT;
	vr->vr_hdr.ioprio = 0;
	kprintf("bsize:%d read:%d bcount:%d bio_offset:%lld %c,%c\n", 
			bp->b_bufsize,isread, bp->b_bcount, (long long)bio->bio_offset,bp->b_data[0],bp->b_data[1]);
	vr->vr_hdr.sector = bio->bio_offset/DEV_BSIZE;
	
	bus_dmamap_sync(sc->requests_dmat, vr->cmd_dmap,
			BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(sc->payloads_dmat, vr->payload_dmap,
			isread?BUS_DMASYNC_PREREAD:BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(sc->requests_dmat, vr->cmd_dmap,
			BUS_DMASYNC_PREREAD);

   
	 
	virtio_enqueue_p(sc, vq, slot, vr, vr->cmd_dmap,
			 0, sizeof(struct virtio_blk_req_hdr),
			 true);
	virtio_enqueue(sc, vq, slot, vr, vr->payload_dmap, !isread);
	virtio_enqueue_p(sc, vq, slot, vr, vr->cmd_dmap,
			 offsetof(struct virtio_blk_req, vr_status),
			 sizeof(uint8_t),
			 false);
	virtio_enqueue_commit(sc, vq, slot, true);
 	return 0;
 	
}
/*
 * Handle an I/O request.
 */
static int
vbd_disk_strategy(struct dev_strategy_args *ap)
{
	kprintf("%s\n--------------\n", __FUNCTION__);
	cdev_t dev = ap->a_head.a_dev;
	struct bio *bio = ap->a_bio;
	struct buf *bp = bio->bio_buf;
	struct virtio_blk_softc *sc = dev->si_drv1;
	/* do-nothing operation? */
	if (bp->b_bcount == 0) {
		kprintf("bp b count is 0\n");
		bp->b_resid = bp->b_bcount;
		biodone(bio);
		return(0);
	}

	devstat_start_transaction(&sc->stats);
	blkvirtio_execute(sc, bio);
	return(1);
}
static int
vbd_disk_close(struct dev_close_args *ap)
{
	kprintf("%s\n", __FUNCTION__);
	return 0;
}
static int
vbd_disk_open(struct dev_open_args *ap)
{
	kprintf("%s\n", __FUNCTION__);
	return 0;
}
static int
vbd_disk_dump(struct dev_dump_args *ap)
{
	kprintf("%s\n", __FUNCTION__);
	return 1;
}
/*
 * Feature negotiation.
 */

/*!
static uint32_t
virtio_negotiate_features(struct virtio_blk_softc *sc, uint32_t guest_features)
{

	uint32_t r;

	guest_features |= VIRTIO_F_RING_INDIRECT_DESC;
	kprintf("and INDIRECT features\n");
	//	}
	r = bus_space_read_4(sc->sc_iot, sc->sc_ioh,
			VIRTIO_CONFIG_DEVICE_FEATURES);
	kprintf("%s: r:0x%x.....x410f0020\n", __FUNCTION__, r);
	r &= guest_features;
	bus_space_write_4(sc->sc_iot, sc->sc_ioh,
			VIRTIO_CONFIG_GUEST_FEATURES, r);
	sc->sc_features = r;
	if (r & VIRTIO_F_RING_INDIRECT_DESC){
		kprintf("%s: indirect true\n", __FUNCTION__);
		sc->sc_indirect = true;
	}
	else{
		kprintf("%s: indirect false\n", __FUNCTION__);
		sc->sc_indirect = false;
	}
	return r;
}

*/

/*!
static void
virtio_set_status(struct virtio_blk_softc *sc, int status)
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

*/

static int virtio_blk_probe(device_t dev)
{
	u_int32_t id = pci_get_device(dev);
	kprintf("%s product_id:%d\n", __FUNCTION__,id);
	if (id >= 0x1000  && id <= 0x103f){
		//bus_generic_probe(dev);
		if (pci_read_config(dev, PCIR_SUBDEV_0, 2) == PCI_PRODUCT_VIRTIO_BLOCK) {
			return 0;
		}
	}

	return 1;
}

/*
 * Initialize vq structure.
 */
/*! already in virtio.c
static void
virtio_init_vq(struct virtio_blk_softc *sc, struct virtqueue *vq)
{
	int i, j;
	int vq_size = vq->vq_num;

	memset(vq->vq_vaddr, 0, vq->vq_bytesize);

	// build the indirect descriptor chain
	if (vq->vq_indirect != NULL) {
		struct vring_desc *vd;

		for (i = 0; i < vq_size; i++) {
			vd = vq->vq_indirect;
			vd += vq->vq_maxnsegs * i;
			for (j = 0; j < vq->vq_maxnsegs-1; j++)
				vd[j].next = j + 1;
		}
	}

	/* free slot management
	TAILQ_INIT(&vq->vq_freelist);
	for (i = 0; i < vq_size; i++) {
		TAILQ_INSERT_TAIL(&vq->vq_freelist,
				    &vq->vq_entries[i], qe_list);
		vq->vq_entries[i].qe_index = i;
	}
	spin_init(&vq->vq_freelist_lock);

	/* enqueue/dequeue status
	vq->vq_avail_idx = 0;
	vq->vq_used_idx = 0;
	vq->vq_queued = 0;
	spin_init(&vq->vq_aring_lock);
	spin_init(&vq->vq_uring_lock);
	vq_sync_aring(sc, vq, BUS_DMASYNC_PREWRITE);
	vq_sync_uring(sc, vq, BUS_DMASYNC_PREREAD);
	vq->vq_queued++;
}

*/

/*! already in virtio.c
static void
virtio_helper(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct virtqueue *vq = (struct virtqueue *) arg;
    kprintf("%s %u\n",__FUNCTION__,(uint)segs->ds_addr);

    vq->bus_addr = segs->ds_addr;
}

*/

/*! already in virtio.c

static int
virtio_alloc_vq(struct virtio_blk_softc *sc,
		struct virtqueue *vq, int index, int maxsegsize, int maxnsegs,
		const char *name)
{
	int vq_size, allocsize1, allocsize2, allocsize3, allocsize = 0;
	int  r;
#define VIRTQUEUE_ALIGN(n)	(((n)+(VIRTIO_PAGE_SIZE-1))& ~(VIRTIO_PAGE_SIZE-1))
	kprintf("%s\n-------\n",__FUNCTION__);
	memset(vq, 0, sizeof(*vq));

	bus_space_write_2(sc->sc_iot, sc->sc_ioh,
			  VIRTIO_CONFIG_QUEUE_SELECT, index);
	vq_size = bus_space_read_2(sc->sc_iot, sc->sc_ioh,
				   VIRTIO_CONFIG_QUEUE_SIZE);
	if (vq_size == 0) {
		kprintf( "virtqueue not exist, index %d for %s\n",
				 index, name);
	}
	kprintf("vq_size:%d\n", vq_size);

	/* allocsize1: descriptor table + avail ring + pad /
	allocsize1 = VIRTQUEUE_ALIGN(sizeof(struct vring_desc)*vq_size
				     + sizeof(uint16_t)*(2+vq_size));
	/* allocsize2: used ring + pad /
	allocsize2 = VIRTQUEUE_ALIGN(sizeof(uint16_t)*2
				     + sizeof(struct vring_used_elem)*vq_size);
	/* allocsize3: indirect table /
	if (sc->sc_indirect && maxnsegs >= MINSEG_INDIRECT)
		allocsize3 = sizeof(struct vring_desc) * maxnsegs * vq_size;
	else
		allocsize3 = 0;
	allocsize = allocsize1 + allocsize2 + allocsize3;
	kprintf("a1:%d a2:%d a3:%d a4:%d\n",
			allocsize1, allocsize2,allocsize3, allocsize);

	int error;
	if (sc->virtio_dmat== NULL){
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

	/*error = bus_dmamap_create(vq->vq_dmat, BUS_DMA_NOWAIT, &vq->vq_dmamap);
	if (error) {
		return error;
	}/

	if (bus_dmamem_alloc(vq->vq_dmat, (void **)&vq->vq_vaddr,
			BUS_DMA_NOWAIT,&vq->vq_dmamap)) {
		kprintf("bus_dmammem_load bad");
		return(ENOMEM);
	}

	if (bus_dmamap_load(vq->vq_dmat, vq->vq_dmamap, vq->vq_vaddr,
	            allocsize, virtio_helper, vq, BUS_DMA_NOWAIT) != 0){
		kprintf("bus_dmamap_load bad");
	}

	/* set the vq address /
	bus_space_write_4(sc->sc_iot,
			sc->sc_ioh,
			  VIRTIO_CONFIG_QUEUE_ADDRESS,
			  //(vq->vq_dmamap->dm_segs[0].ds_addr / VIRTIO_PAGE_SIZE));
			  (vq->bus_addr / VIRTIO_PAGE_SIZE));
	//kprintf("bus_addr is %u\n",vq->bus_addr);

	/* remember addresses and offsets for later use /
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

	kprintf("vq_num:%u, vq_index:%u, vq_desc:%p, vq_availoffset:%u\n",
            vq->vq_num,
            vq->vq_index,
            vq->vq_desc,
            vq->vq_availoffset);
    kprintf("vq_avail:%p, vq_usedoffset:%u, vq_used:%p\n",
            vq->vq_avail,
            vq->vq_usedoffset,
            vq->vq_used);
    kprintf("vq_bytesize:%u, vq_maxsegsize:%u, vq_maxnsegs:%u\n",
            vq->vq_bytesize, vq->vq_maxsegsize, vq->vq_maxnsegs);


	/* free slot management /
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

*/


/*!
static void
vq_free_entry(struct virtqueue *vq, struct vq_entry *qe)
{
	spin_lock(&vq->vq_freelist_lock);
	TAILQ_INSERT_TAIL(&vq->vq_freelist, qe, qe_list);
	spin_unlock(&vq->vq_freelist_lock);

	return;
}

*/

/*
 * dequeue_commit: complete dequeue; the slot is recycled for future use.
 *                 if you forget to call this the slot will be leaked.
 */

/*!
static int
virtio_dequeue_commit(struct virtio_blk_softc *sc, struct virtqueue *vq, int slot)
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


*/
static void
ld_virtio_vq_done1(struct virtio_blk_softc *sc,
		   struct virtqueue *vq, int slot)
{
	struct virtio_blk_req *vr = &sc->sc_reqs[slot];
	struct buf *bp = vr->vr_bp;

	bus_dmamap_sync(sc->requests_dmat, vr->cmd_dmap,
			//0, sizeof(struct virtio_blk_req_hdr),
			BUS_DMASYNC_POSTWRITE);
	bus_dmamap_sync(sc->payloads_dmat, vr->payload_dmap,
	//		0, bp->b_bcount,
	(bp->b_cmd & BUF_CMD_READ)?BUS_DMASYNC_POSTREAD
					      :BUS_DMASYNC_POSTWRITE);
	bus_dmamap_sync(sc->requests_dmat, vr->cmd_dmap,
//			sizeof(struct virtio_blk_req_hdr), sizeof(uint8_t),
			BUS_DMASYNC_POSTREAD);

	if (vr->vr_status != VIRTIO_BLK_S_OK) {
		bp->b_error = EIO;
		bp->b_resid = bp->b_bcount;
		kprintf("blk not ok\n");
	} else {
		bp->b_error = 0;
		bp->b_resid = 0;
	}

	virtio_dequeue_commit(sc, vq, slot);
	devstat_end_transaction_buf(&sc->stats, bp);
	kprintf("%s %d %p %p %c:%c\n",__FUNCTION__,  slot, (void *)&bp->b_bio_array[0],(void *)&bp->b_bio_array[1], bp->b_data[0],bp->b_data[511]);
	biodone(&bp->b_bio_array[1]);
	//lddone(&sc->sc_ld, bp);
}

/*
 * Dequeue a request.
 */
/*
 * dequeue: dequeue a request from uring; dmamap_sync for uring is
 *	    already done in the interrupt handler.
 */

/*!
static int
virtio_dequeue(struct virtio_blk_softc *sc, struct virtqueue *vq,
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

*/

static int
ld_virtio_vq_done(struct virtqueue *vq)
{
	struct virtio_blk_softc *sc = vq->vq_owner;
	//struct ld_virtio_softc *sc = device_private(vsc->sc_child);
	int r = 0;
	int slot;

again:
	if (virtio_dequeue(sc, vq, &slot, NULL))
		return r;
	r = 1;

	ld_virtio_vq_done1(sc, vq, slot);
	goto again;
}


static void
virtio_cmds_helper(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct virtio_blk_softc *sc = (struct virtio_blk_softc *)arg;
	///*struct virtqueue *vq = (struct virtqueue *) arg;
	sc->sc_reqs = (struct virtio_blk_req*) segs[0].ds_addr;
    //kprintf("%s %d %p %x\n",__FUNCTION__, nseg, sc->sc_reqs,segs[0].ds_addr);
}

static void
virtio_cmd_helper(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct virtio_blk_req *req = (struct virtio_blk_req*) arg;
	req->ds_addr = segs[0].ds_addr;
	req->ds_len=segs[0].ds_len;	
	kprintf("%s addr:%p len:%lu nseg:%u\n",
			__FUNCTION__,(void*) segs[0].ds_addr, segs[0].ds_len, nseg);
}

static int
ld_virtio_alloc_reqs(struct virtio_blk_softc *sc, int qsize)
{
	/*Create tag commands*/
	void * vaddr;
	int error,i;
	
	int allocsize = sizeof(struct virtio_blk_req) * qsize;
	//int payload_allocsize = 65536 * qsize;

	if (bus_dma_tag_create(sc->virtio_dmat,
						   1,
						   0,
						   BUS_SPACE_MAXADDR,
						   BUS_SPACE_MAXADDR,
						   NULL, NULL,
						   allocsize,
						   1,
						   allocsize,
						   BUS_DMA_ALLOCNOW,
						   &sc->requests_dmat) != 0) {
		kprintf("cmd_dmat tag create failed\n");
		return(1);
	}

	if (bus_dma_tag_create(sc->virtio_dmat,
						   1,
						   0,
						   BUS_SPACE_MAXADDR,
						   BUS_SPACE_MAXADDR,
						   NULL, NULL,
						   BUS_SPACE_MAXSIZE_24BIT,
						   30,
						   BUS_SPACE_MAXSIZE_24BIT,
						   BUS_DMA_ALIGNED,
						   &sc->payloads_dmat) != 0) {
		kprintf("cmd_dmat tag create failed\n");
		return(1);
	}
  
	if (bus_dmamem_alloc(sc->requests_dmat, (void **)&vaddr,
					 BUS_DMA_NOWAIT,&sc->cmds_dmamap)) {
		kprintf("bus_dmammem_load bad");
		return(ENOMEM);
	}

	if (bus_dmamap_load(sc->requests_dmat,
							sc->cmds_dmamap, 
							vaddr,
							allocsize, 
							virtio_cmds_helper, sc, BUS_DMA_NOWAIT) != 0) {
			kprintf("bus_dmamap_load bad");
			return 1;
	}
	sc->sc_reqs = vaddr;
	kprintf("vaddr:%p, qsize:%d\n", vaddr,qsize);
	for (i = 0; i< qsize; i++) { 
		struct virtio_blk_req *vr = &sc->sc_reqs[i]; 
		

		error = bus_dmamap_create(sc->requests_dmat,BUS_DMA_NOWAIT, &vr->cmd_dmap);
		if (error) {
			kprintf("bus_dmamap_create error\n");
			return 1;
		}
		
		if (bus_dmamap_load(sc->requests_dmat,
							vr->cmd_dmap, 
							&vr->vr_hdr,
							24,//offsetof(struct virtio_blk_req, vr_bp),
							virtio_cmd_helper, vr, 0/*BUS_DMA_NOWAIT*/) != 0) {
			kprintf("bus_dmamap_load bad");
			return 1;
		}
		//kprintf("i:%d %p vr:%u %u \n",i,vr, vr->ds_len, &vr->vr_hdr);

		error = bus_dmamap_create(sc->payloads_dmat, 0, &vr->payload_dmap);
		if (error) {
			kprintf("bus_dmamap_create error\n");
			return 1;
		}
		
	}
	kprintf("%s done\n", __FUNCTION__);


	return 0;
}

/*! already in virtio.c

static int
virtio_intr(void *arg)
{

	struct virtio_blk_softc *sc = arg;
	int isr, r = 0;

	// check and ack the interrupt
	isr = bus_space_read_1(sc->sc_iot, sc->sc_ioh,
						   VIRTIO_CONFIG_ISR_STATUS);

//	kprintf("%s isr:%d %p\n", __FUNCTION__,isr,sc->sc_intrhand );

	if (isr == 0)
		return 0;
	if ((isr & VIRTIO_CONFIG_ISR_CONFIG_CHANGE) &&
		(sc->sc_config_change != NULL)){
		kprintf("config change\n");
		r = (sc->sc_config_change)(sc);
	}
	if (sc->sc_intrhand != NULL){
		//kprintf("interrupt handle\n");
		r |= (sc->sc_intrhand)(sc);
	}
	
	return r;
};
!*/

/*
 * Can be used as sc_intrhand.
 */
/*
 * Scan vq, bus_dmamap_sync for the vqs (not for the payload),
 * and calls (*vq_done)() if some entries are consumed.
 */

/*!
static int
virtio_vq_intr(struct virtio_blk_softc *sc)
{
	struct virtqueue *vq;
	int  r = 0;

	//for (i = 0; i < sc->sc_nvqs; i++) {
		vq = &sc->sc_vq;
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
	//}
		

	return r;
}

*/

static int virtio_blk_attach(device_t dev)
{
	struct virtio_blk_softc *sc = device_get_softc(dev);
	struct resource *io;
	sc->dev = dev;
	int rid,error;
	int features;
	int  qsize;
    struct disk_info info;

	kprintf("%s\n",__FUNCTION__);
	rid = PCIR_BAR(0);
	io = bus_alloc_resource(dev, SYS_RES_IOPORT, &rid,
			0, ~0, 1, RF_ACTIVE);
	if (!io) {
		device_printf(dev, "No I/O space?!\n");
		return ENOMEM;
	}
	sc->sc_iot = rman_get_bustag(io);
	sc->sc_ioh = rman_get_bushandle(io);
    sc->sc_config_offset = VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI;
	sc->sc_config_change = 0;
	sc->sc_intrhand = virtio_vq_intr;

	kprintf("%u %u\n", (unsigned int) sc->sc_iot,(unsigned int)sc->sc_ioh);
	kprintf("%d Virtio %s Device (rev. 0x%02x)\n",
			pci_get_vendor(dev),
			(pci_read_config(dev, PCIR_SUBDEV_0, 2)<NDEVNAMES?
			 virtio_device_name[pci_read_config(dev, PCIR_SUBDEV_0, 2)]:"Unknown"),
			pci_read_config(dev, PCIR_REVID, 1));

	sc->res_irq = bus_alloc_resource_any(sc->dev, SYS_RES_IRQ,
			&sc->rid_irq, RF_SHAREABLE|RF_ACTIVE);
	kprintf("rid_irq:%d\n", sc->rid_irq);
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
	error = bus_dma_tag_create(NULL,
			1,
			0,
			BUS_SPACE_MAXADDR,
			BUS_SPACE_MAXADDR,
			NULL, NULL,
	        BUS_SPACE_MAXSIZE_32BIT,
			0,
	        BUS_SPACE_MAXSIZE_32BIT,
			0,
			&sc->virtio_dmat);

	if (error ) {
		kprintf("error");
		return 1;
	}

 	virtio_set_status(sc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK); 

	/*Block attach stuff*/
    device_set_desc(dev, "virtio-blk");

	features = virtio_negotiate_features(sc,
			(VIRTIO_BLK_F_SIZE_MAX |
			 VIRTIO_BLK_F_SEG_MAX |
			 VIRTIO_BLK_F_GEOMETRY |
			 VIRTIO_BLK_F_RO |
			 VIRTIO_BLK_F_BLK_SIZE |
			 VIRTIO_BLK_F_SECTOR_MAX));
	kprintf("features:0x%x\n", features); 

	if (features & VIRTIO_BLK_F_RO){
		kprintf("is readonly\n");
		sc->sc_readonly = 1;
	} else{
		kprintf("is not readonly\n");
		sc->sc_readonly = 0;
	}
	kprintf("sc_readonly:%u\n", sc->sc_readonly);

	sc->maxxfersize = MAXPHYS; 
	if (features & VIRTIO_BLK_F_SECTOR_MAX) {
		/*This isn't called for us*/
		sc->maxxfersize = 
			virtio_read_device_config_4(sc, VIRTIO_BLK_CONFIG_SECTORS_MAX)	* 512;
		kprintf("read_device_config maxxfersize:%u\n",sc->maxxfersize);
		if (sc->maxxfersize > MAXPHYS)
			sc->maxxfersize = MAXPHYS;
	}
	kprintf("maxxfersize:%d\n", sc->maxxfersize);

	if (virtio_alloc_vq(sc, &sc->sc_vq, 0,
			    sc->maxxfersize, sc->maxxfersize / NBPG + 2,
			    "I/O request") != 0) {
		kprintf("Bad virtio_alloc_vq\n");
		return 1;
	
	}
	qsize = sc->sc_vq.vq_num;
	sc->sc_vq.vq_done = ld_virtio_vq_done;

	/* construct the disk_info */
    bzero(&info, sizeof(info));

	kprintf("Size is %llu\n",(unsigned long long)
			virtio_read_device_config_8(sc, VIRTIO_BLK_CONFIG_CAPACITY));

	if (features & VIRTIO_BLK_F_BLK_SIZE) {
		kprintf("BLKSIZE feature is %d \n",
				virtio_read_device_config_4(sc,VIRTIO_BLK_CONFIG_BLK_SIZE));
		//info.d_secsize = virtio_read_device_config_4(vsc,
			//		VIRTIO_BLK_CONFIG_BLK_SIZE);
	}

	info.d_media_blksize = DEV_BSIZE;
	info.d_media_blocks =  
		virtio_read_device_config_8(sc, VIRTIO_BLK_CONFIG_CAPACITY);  
	kprintf("Media blocks is %lu\n", info.d_media_blocks);
	if (features & VIRTIO_BLK_F_GEOMETRY) {		


		info.d_ncylinders = virtio_read_device_config_2(sc,
					VIRTIO_BLK_CONFIG_GEOMETRY_C);
		info.d_nheads     = virtio_read_device_config_1(sc,
					VIRTIO_BLK_CONFIG_GEOMETRY_H);
		info.d_secpertrack = virtio_read_device_config_1(sc,
					VIRTIO_BLK_CONFIG_GEOMETRY_S);

		info.d_secpercyl = info.d_secpertrack * info.d_nheads;

		kprintf("c:%u h:%u s:%u\n",
				virtio_read_device_config_2(sc, VIRTIO_BLK_CONFIG_GEOMETRY_C),
				virtio_read_device_config_1(sc, VIRTIO_BLK_CONFIG_GEOMETRY_H),
				virtio_read_device_config_1(sc, VIRTIO_BLK_CONFIG_GEOMETRY_S));
	}
	else{
		kprintf("Features not requested\n");
		return 1;
	}

	if (ld_virtio_alloc_reqs(sc, qsize) < 0)
	{
		kprintf("Bad ld_virtio_alloc_reqs\n");
		return 1;
	}


	devstat_add_entry(&sc->stats, "vbd", device_get_unit(dev),
					  DEV_BSIZE, 
					  DEVSTAT_NO_ORDERED_TAGS,
					  DEVSTAT_TYPE_DIRECT | DEVSTAT_TYPE_IF_OTHER,
					  DEVSTAT_PRIORITY_DISK);

	/* attach a generic disk device to ourselves */
	sc->cdev = disk_create(device_get_unit(dev), &sc->disk,
							   &vbd_disk_ops);

	sc->cdev->si_drv1 = sc;
    disk_setdiskinfo(&sc->disk, &info);
 
	return 0;
}

static device_method_t virtio_blk_methods[] = {
//	DEVMETHOD(device_identify,         virtio_identify),
	DEVMETHOD(device_probe,         virtio_blk_probe),
	DEVMETHOD(device_attach,        virtio_blk_attach),
 //	DEVMETHOD(bus_driver_added,    virtio_bus_driver_added),
//    DEVMETHOD(bus_add_child,    virtio_bus_add_child),

	{ 0, 0 }
};

static driver_t virtio_blk_driver = {
	"virtiobus",
	virtio_blk_methods,
	sizeof(struct virtio_blk_softc),
};

static devclass_t virtio_blk_devclass;

DRIVER_MODULE(virtio_blk, pci, virtio_blk_driver, virtio_blk_devclass, 0, 0);
MODULE_VERSION(virtio_blk, 0);

