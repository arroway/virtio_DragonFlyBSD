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
#include <sys/disk.h>
#include <sys/buf.h>
#include <sys/devicestat.h>
#include <sys/spinlock.h>
#include <sys/spinlock2.h>
#include <bus/pci/pcivar.h>
#include <bus/pci/pcireg.h>

#include "virtiovar.h"
#include "virtioreg.h"

/*
 * ld_virtioreg:
 */

/* Configuration registers */
#define VIRTIO_BLK_CONFIG_CAPACITY	0	/* 64bit */
#define VIRTIO_BLK_CONFIG_SIZE_MAX	8	/* 32bit */
#define VIRTIO_BLK_CONFIG_SEG_MAX	12	/* 32bit */
#define VIRTIO_BLK_CONFIG_GEOMETRY_C	16	/* 16bit */
#define VIRTIO_BLK_CONFIG_GEOMETRY_H	18	/* 8bit */
#define VIRTIO_BLK_CONFIG_GEOMETRY_S	19	/* 8bit */
#define VIRTIO_BLK_CONFIG_BLK_SIZE	20	/* 32bit */
#define VIRTIO_BLK_CONFIG_SECTORS_MAX	24	/* 32bit */

/* Feature bits */
#define VIRTIO_BLK_F_BARRIER		(1<<0)
#define VIRTIO_BLK_F_SIZE_MAX		(1<<1)
#define VIRTIO_BLK_F_SEG_MAX		(1<<2)
#define VIRTIO_BLK_F_GEOMETRY		(1<<4)
#define VIRTIO_BLK_F_RO			(1<<5)
#define VIRTIO_BLK_F_BLK_SIZE		(1<<6)
#define VIRTIO_BLK_F_SCSI		(1<<7)
#define VIRTIO_BLK_F_FLUSH		(1<<9)
#define VIRTIO_BLK_F_SECTOR_MAX		(1<<10)

/* Command */
#define VIRTIO_BLK_T_IN			0
#define VIRTIO_BLK_T_OUT		1
#define VIRTIO_BLK_T_BARRIER		0x80000000

/* Status */
#define VIRTIO_BLK_S_OK			0
#define VIRTIO_BLK_S_IOERR		1


/* Request header structure */
struct virtio_blk_req_hdr {
	uint32_t	type;	/* VIRTIO_BLK_T_* */
	uint32_t	ioprio;
	uint64_t	sector;
} __packed;

struct virtio_blk_bio {
	TAILQ_ENTRY(virtio_blk_bio)	vbb_list; /* free list */
	struct bio			*bio;
};

/* 512*virtio_blk_req_hdr.sector byte payload and 1 byte status follows */
/*
 * ld_virtiovar:
 */
struct virtio_blk_req {
	struct virtio_blk_req_hdr	vr_hdr;
	uint8_t			vr_status;
	struct buf		*vr_bp;

	bus_dmamap_t		cmd_dmap;
	bus_addr_t		ds_addr;	/* DMA address */
	bus_size_t		ds_len;	/* length of transfer */

	bus_dmamap_t		payload_dmap;
	bus_dma_segment_t	*segs;
	int nseg;
};

struct virtio_blk_softc {
	device_t		dev;
	struct virtio_softc	*sc_virtio;
	struct virtqueue	sc_vq[1]; 
	int			sc_readonly; 
	int			maxxfersize;

	/*Block Device Specific*/
	cdev_t			cdev;
	struct devstat		stats;
	struct disk		disk;

	struct virtio_blk_req	*sc_reqs;
	/*throttle outstanding ios*/
	TAILQ_HEAD(, virtio_blk_bio)	vbb_queue;	
	struct spinlock		vbb_queue_lock;
};

/*
 * Interface to the device switch.
 */
static d_open_t		virtio_disk_open;
static d_close_t	virtio_disk_close;
static d_strategy_t	virtio_disk_strategy;
static d_dump_t		virtio_disk_dump;

static struct dev_ops vbd_disk_ops = {
	{ "vbd", 200, D_DISK},
	.d_open		= virtio_disk_open,
	.d_close	= virtio_disk_close,
	.d_read		= physread,
	.d_write	= physwrite,
	.d_strategy	= virtio_disk_strategy,
	.d_dump		= virtio_disk_dump,
} ;

/* Declarations */
static int	virtio_blk_execute(struct virtio_blk_softc *sc);
static void	virtio_blk_vq_done1(struct virtio_blk_softc *sc,
				    struct virtio_softc *vsc,
				    struct virtqueue *vq, int slot);
static int virtio_blk_vq_done(struct virtqueue *vq);
static void virtio_cmds_helper(void *arg, bus_dma_segment_t *segs, int nseg,
			       int error);
static void virtio_cmd_helper(void *arg, bus_dma_segment_t *segs, int nseg,
			      int error);
static int virtio_blk_alloc_reqs(struct virtio_blk_softc *sc, int qsize);
static int virtio_blk_probe(device_t dev);
static int virtio_blk_attach(device_t dev);
static int virtio_blk_detach(device_t dev);

static void
map_payload(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct virtio_blk_req *vr = (struct virtio_blk_req *) arg;
	vr->segs = segs;
	vr->nseg = nseg;
	debug("%p:%p addr:%lu, len:%lu\n", segs,vr->segs,vr->segs[0].ds_addr,
	      vr->segs[0].ds_len);
}

static int
virtio_blk_execute(struct virtio_blk_softc *sc)
{
	struct virtqueue *vq = &sc->sc_vq[0];
	struct virtio_softc *vsc = sc->sc_virtio;
	struct bio* bio;
	struct virtio_blk_bio* vbb = NULL;
	struct buf *bp; 
	int isread;
	int r;
	int slot;
	struct virtio_blk_req *vr;



	spin_lock(&sc->vbb_queue_lock);     
	vbb = TAILQ_FIRST(&sc->vbb_queue);
	if (vbb == NULL) {
		spin_unlock(&sc->vbb_queue_lock);
		return 1;
	}
	TAILQ_REMOVE(&sc->vbb_queue, vbb, vbb_list);
	spin_unlock(&sc->vbb_queue_lock);

	r = virtio_enqueue_prep(vsc, vq, &slot);
	if (r != 0) {
		kprintf("%u slots\n", slot);
		kprintf("virtio_blk_execute: no slot available in vq.\n We requeue.\n ");
		/* We need to requeue this guy as there was no slot*/
		spin_lock(&sc->vbb_queue_lock);
		TAILQ_INSERT_TAIL(&sc->vbb_queue, vbb, vbb_list);
		spin_unlock(&sc->vbb_queue_lock);

		return r;
	}

	bio = vbb->bio;
	//kfree(vbb, M_DEVBUF);
	bp = bio->bio_buf;
	vr = &sc->sc_reqs[slot];
	isread= (bp->b_cmd & BUF_CMD_READ);
	if (sc->sc_readonly && !isread) {
		kprintf("is read only:%u but op is not\n", sc->sc_readonly);
		/*XXX: free slot here?*/

		return EIO;
	}

	devstat_start_transaction(&sc->stats);
	r = bus_dmamap_load(sc->sc_virtio->payloads_dmat,
			    vr->payload_dmap,
			    bp->b_data, 
			    bp->b_bcount, 
			    map_payload,
			    vr, 
			    0);
	if (r != 0) {
		kprintf("Bad bus_dmamap_load\n");
		return r;
	}

	// pourquoi vr->nseg + 2 ?
	r = virtio_enqueue_reserve(vsc, vq, slot, vr->nseg + 2);
	if (r != 0) {
		kprintf("Bad enqueue_reserve\n");

		//we enqueue again vbb in vbb_list
		spin_lock(&sc->vbb_queue_lock);
		TAILQ_INSERT_TAIL(&sc->vbb_queue, vbb, vbb_list);
		spin_unlock(&sc->vbb_queue_lock);
		return r;
	}

	kfree(vbb, M_DEVBUF);

	vr->vr_bp = bp;
	vr->vr_hdr.type = isread?VIRTIO_BLK_T_IN:VIRTIO_BLK_T_OUT;
	vr->vr_hdr.ioprio = 0;
	debug("bsize:%d read:%d bcount:%d bio_offset:%lld\n",
		bp->b_bufsize,isread, bp->b_bcount, (long long)bio->bio_offset);
	vr->vr_hdr.sector = bio->bio_offset/DEV_BSIZE;

	bus_dmamap_sync(vsc->requests_dmat, vr->cmd_dmap, BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(vsc->payloads_dmat, vr->payload_dmap, 
		isread?BUS_DMASYNC_PREREAD:BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(vsc->requests_dmat, vr->cmd_dmap, BUS_DMASYNC_PREREAD);

	virtio_enqueue_p(vsc, vq, slot, vr->ds_addr, vr->ds_len, vr->cmd_dmap,
			 0, sizeof(struct virtio_blk_req_hdr), true);
	virtio_enqueue(vsc, vq, slot, vr->segs, vr->nseg, vr->payload_dmap,
		       !isread);
	virtio_enqueue_p(vsc, vq, slot, vr->ds_addr, vr->ds_len, vr->cmd_dmap,
			 offsetof(struct virtio_blk_req, vr_status),
			 sizeof(uint8_t), false);
	virtio_enqueue_commit(vsc, vq, slot, true);
	return 0;

}

/*  Handle an I/O request. */
static int
virtio_disk_strategy(struct dev_strategy_args *ap)
{
	debug("\n--------------\n");
	cdev_t dev = ap->a_head.a_dev;
	struct bio *bio = ap->a_bio;
	struct buf *bp = bio->bio_buf;
	struct virtio_blk_softc *sc = dev->si_drv1;

	if (bp->b_bcount == 0) {
		debug("bp b count is 0\n");
		bp->b_resid = bp->b_bcount;
		biodone(bio);
		return(0);
	}

	struct virtio_blk_bio * vbb = 
	kmalloc(sizeof(struct virtio_blk_bio),M_DEVBUF, 0);
	vbb->bio = bio;

	/*
	* Queue an I/O request. Enforce that only qsize
	* slots are used
	*/
	spin_lock(&sc->vbb_queue_lock);
	TAILQ_INSERT_TAIL(&sc->vbb_queue, vbb, vbb_list);
	spin_unlock(&sc->vbb_queue_lock);


	virtio_blk_execute(sc);
	return(0); 
}

static int
virtio_disk_close(struct dev_close_args *ap)
{

	//decr cdev->usecount
	//in detach: only unload if the counter is = 0
	debug("%s\n", __FUNCTION__);
	return 0;
}
static int
virtio_disk_open(struct dev_open_args *ap)
{
	//incr cdev->usecount
	debug("%s\n", __FUNCTION__);
	return 0;
}
static int
virtio_disk_dump(struct dev_dump_args *ap)
{
	kprintf("%s\n", __FUNCTION__);
	return 1;
}


static void
virtio_blk_vq_done1(struct virtio_blk_softc *sc, struct virtio_softc *vsc,
					struct virtqueue *vq, int slot)
{
	struct virtio_blk_req *vr = &sc->sc_reqs[slot];
	struct buf *bp = vr->vr_bp;

	bus_dmamap_sync(vsc->requests_dmat, vr->cmd_dmap,
			BUS_DMASYNC_POSTWRITE);
	bus_dmamap_sync(vsc->payloads_dmat, vr->payload_dmap, 
			(bp->b_cmd & BUF_CMD_READ)?
			BUS_DMASYNC_POSTREAD:
			BUS_DMASYNC_POSTWRITE);
	bus_dmamap_sync(vsc->requests_dmat, vr->cmd_dmap, BUS_DMASYNC_POSTREAD);

	if (vr->vr_status != VIRTIO_BLK_S_OK) {
		bp->b_error = EIO;
		bp->b_resid = bp->b_bcount;
		kprintf("blk not ok\n");
	} else {
		bp->b_error = 0;
		bp->b_resid = 0;
	}

	virtio_dequeue_commit(vsc, vq, slot);
	devstat_end_transaction_buf(&sc->stats, bp);
	debug("%d %p %p %c:%c\n",slot, (void *)&bp->b_bio_array[0],
		(void *)&bp->b_bio_array[1], bp->b_data[0],bp->b_data[511]);
	biodone(&bp->b_bio_array[1]);
}


static int
virtio_blk_vq_done(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct virtio_blk_softc *sc = device_get_softc(vsc->sc_child);
	int r = 0;
	int slot;

again:
	if (virtio_dequeue(vsc, vq, &slot, NULL)) {
		int empty;

		empty = TAILQ_EMPTY(&sc->vbb_queue); 
		if (!empty) {
			virtio_blk_execute(sc);
		}
		return r;
	}
	r = 1;

	virtio_blk_vq_done1(sc, vsc, vq, slot);
	goto again; 

}

static void
virtio_cmds_helper(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct virtio_blk_softc *sc = (struct virtio_blk_softc *)arg;
	sc->sc_reqs = (struct virtio_blk_req*) segs[0].ds_addr;
}

static void
virtio_cmd_helper(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct virtio_blk_req *req = (struct virtio_blk_req*) arg;
	req->ds_addr = segs[0].ds_addr;
	req->ds_len=segs[0].ds_len; 
}

static int
virtio_blk_alloc_reqs(struct virtio_blk_softc *sc, int qsize)
{
	/*Create tag commands*/
	void * vaddr;
	int error,i;
	device_t pdev = device_get_parent(sc->dev);
	struct virtio_softc *vsc = device_get_softc(pdev);
	int allocsize = sizeof(struct virtio_blk_req) * qsize;

	error = bus_dma_tag_create(vsc->virtio_dmat,
				1,
				0,
				BUS_SPACE_MAXADDR,
				BUS_SPACE_MAXADDR,
				NULL, NULL,
				allocsize,
				1,
				allocsize,
				BUS_DMA_ALLOCNOW,
				&vsc->requests_dmat);
	if (error != 0) {
		kprintf("cmd_dmat tag create failed\n");
		return(1);
	}

	error = bus_dma_tag_create(vsc->virtio_dmat,
				1,
				0,
				BUS_SPACE_MAXADDR,
				BUS_SPACE_MAXADDR,
				NULL, NULL,
				BUS_SPACE_MAXSIZE_24BIT,
				30,
				BUS_SPACE_MAXSIZE_24BIT,
				BUS_DMA_ALIGNED,
				&vsc->payloads_dmat);
	if (error != 0) {
		kprintf("cmd_dmat tag create failed\n");
		return(1);
	}

	error = bus_dmamem_alloc(vsc->requests_dmat,
				(void **)&vaddr, 
				BUS_DMA_NOWAIT,
				&vsc->cmds_dmamap);
	if (error != 0) {
		kprintf("bus_dmammem_load bad");
		return(ENOMEM);
	}

	error = bus_dmamap_load(vsc->requests_dmat,
				vsc->cmds_dmamap, 
				vaddr,
				allocsize, 
				virtio_cmds_helper,
				sc,
				BUS_DMA_NOWAIT);
	if (error != 0) {
		kprintf("bus_dmamap_load bad");
		return 1;
	}

	sc->sc_reqs = vaddr;
	debug("vaddr:%p, qsize:%d\n", vaddr,qsize);
	for (i = 0; i< qsize; i++) {
		struct virtio_blk_req *vr = &sc->sc_reqs[i]; 

		error = bus_dmamap_create(vsc->requests_dmat,
					BUS_DMA_NOWAIT, 
					&vr->cmd_dmap);
		if (error) {
			kprintf("bus_dmamap_create error\n");
			return 1;
		}

		error = bus_dmamap_load(vsc->requests_dmat,
					vr->cmd_dmap, 
					&vr->vr_hdr,
					offsetof(struct virtio_blk_req, vr_bp),
					virtio_cmd_helper, vr, 0/*BUS_DMA_NOWAIT*/);
		if (error  != 0) {
			kprintf("bus_dmamap_load bad");
			return 1;
		}

		error = bus_dmamap_create(vsc->payloads_dmat, 0, &vr->payload_dmap);
		if (error) {
			kprintf("bus_dmamap_create error\n");
			return 1;
		}
	}

	debug("done\n");
	return 0;
}


static int 
virtio_blk_probe(device_t dev)
{
	device_t pdev = device_get_parent(dev);
	/*probe is only called if identify adds the child device.*/

	if (pci_read_config(pdev, PCIR_SUBDEV_0, 2) == PCI_PRODUCT_VIRTIO_BLOCK) {
		debug("parent:%p is block\n", pdev);
	} else {
		debug("parent:%p is not block\n");
		return 1;
	}

	return 0;
}


static int 
virtio_blk_attach(device_t dev)
{
	struct virtio_blk_softc *sc = device_get_softc(dev);
	device_t pdev = device_get_parent(dev);
	struct virtio_softc *vsc     = device_get_softc(pdev);
	uint32_t features;
	int qsize;
	struct disk_info info;
	int error;
	debug("");

	sc->dev = dev;
	sc->sc_virtio = vsc;

	vsc->sc_vqs = &sc->sc_vq[0];
	vsc->sc_nvqs = 1;
	vsc->sc_config_change = 0;
	vsc->sc_child = dev;
	vsc->sc_intrhand = virtio_vq_intr;
	debug("sc_child is %p\n", vsc->sc_child);
	features = virtio_negotiate_features(vsc,
				   (VIRTIO_BLK_F_SIZE_MAX |
				   VIRTIO_BLK_F_SEG_MAX |
				   VIRTIO_BLK_F_GEOMETRY |
				   VIRTIO_BLK_F_RO |
				   VIRTIO_BLK_F_BLK_SIZE |
				   VIRTIO_BLK_F_SECTOR_MAX));

	if (features & VIRTIO_BLK_F_RO)
		sc->sc_readonly = 1;
	else
		sc->sc_readonly	= 0;

	sc->maxxfersize = MAXPHYS;
	if (features & VIRTIO_BLK_F_SECTOR_MAX) {
		sc->maxxfersize = virtio_read_device_config_4(vsc, 
					  VIRTIO_BLK_CONFIG_SECTORS_MAX) * 512;
		if (sc->maxxfersize > MAXPHYS)
			sc->maxxfersize = MAXPHYS;
	}

	error = virtio_alloc_vq(vsc, &sc->sc_vq[0], 0, sc->maxxfersize,
				(sc->maxxfersize / VIRTIO_PAGE_SIZE) + 2,
				"I/O request");
	if(error != 0) {
		goto err;
	}

	qsize = sc->sc_vq[0].vq_num;
	sc->sc_vq[0].vq_done = virtio_blk_vq_done;

	/* construct the disk_info */
	bzero(&info, sizeof(info));

	info.d_media_blksize = DEV_BSIZE;
	info.d_media_blocks =  
	virtio_read_device_config_8(vsc, VIRTIO_BLK_CONFIG_CAPACITY);  
	if (features & VIRTIO_BLK_F_GEOMETRY) {
		info.d_ncylinders = virtio_read_device_config_2(vsc, 
						VIRTIO_BLK_CONFIG_GEOMETRY_C);
		info.d_nheads = virtio_read_device_config_1(vsc, 
						VIRTIO_BLK_CONFIG_GEOMETRY_H);
		info.d_secpertrack = virtio_read_device_config_1(vsc, 
						VIRTIO_BLK_CONFIG_GEOMETRY_S);
		info.d_secpercyl = info.d_secpertrack * info.d_nheads;
	} else {
		kprintf("Backend not reporting CHS\n");
		goto err;
	}

	if (virtio_blk_alloc_reqs(sc, qsize) < 0) {
		kprintf("Request allocation failed\n");
		goto err;
	}

	devstat_add_entry(&sc->stats, "vbd", device_get_unit(dev), 
			  DEV_BSIZE, 
			  DEVSTAT_NO_ORDERED_TAGS, 
			  DEVSTAT_TYPE_DIRECT | DEVSTAT_TYPE_IF_OTHER, 
			  DEVSTAT_PRIORITY_DISK);

	/* attach a generic disk device to ourselves */
	sc->cdev = disk_create(device_get_unit(dev), &sc->disk,	&vbd_disk_ops);

	TAILQ_INIT(&sc->vbb_queue);
	spin_init(&sc->vbb_queue_lock);


	sc->cdev->si_drv1 = sc;
	disk_setdiskinfo(&sc->disk, &info);


	virtio_set_status(vsc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);

	return 0;
err:
	kprintf("%s failure\n", __FUNCTION__);
	return 1;
}

static int 
virtio_blk_detach(device_t dev)
{
	kprintf("%s \n",__FUNCTION__);
	struct virtio_blk_softc *sc = device_get_softc(dev);
	device_t pdev = device_get_parent(sc->dev);
	struct virtio_softc *vsc = device_get_softc(pdev);
	struct virtqueue *vq = &sc->sc_vq[0];
	int i;

	for (i=0; i<sc->sc_vq[0].vq_num; i++) {
		struct virtio_blk_req *vr = &sc->sc_reqs[i]; 

		bus_dmamap_destroy(vsc->payloads_dmat, vr->payload_dmap);

		bus_dmamap_unload(vsc->requests_dmat, vr->cmd_dmap);
		bus_dmamap_destroy(vsc->requests_dmat, vr->cmd_dmap);
	}

	bus_dmamap_unload(vsc->requests_dmat, vsc->cmds_dmamap);
	bus_dmamem_free(vsc->requests_dmat, sc->sc_reqs, vsc->cmds_dmamap);

	bus_dma_tag_destroy(vsc->payloads_dmat);
	bus_dma_tag_destroy(vsc->requests_dmat);

	virtio_reset(vsc);

	virtio_free_vq(vsc, &sc->sc_vq[0]);

	/*unload and free virtqueue*/
	/* bug fix */
	// freed twice
	//kfree(vq->vq_entries, M_DEVBUF);
	bus_dmamap_unload(vq->vq_dmat, vq->vq_dmamap);
	bus_dmamem_free(vq->vq_dmat, vq->vq_vaddr, vq->vq_dmamap);
	bus_dma_tag_destroy(vq->vq_dmat);
	memset(vq, 0, sizeof(*vq));

	/*free dev disk/stat */
	disk_invalidate(&sc->disk);
	disk_destroy(&sc->disk);
	devstat_remove_entry(&sc->stats);


	return 0;
}

static device_method_t virtio_blk_methods[] = {
	DEVMETHOD(device_probe,		virtio_blk_probe),
	DEVMETHOD(device_attach,	virtio_blk_attach),
	DEVMETHOD(device_detach,	virtio_blk_detach),
	{ 0, 0 }
};

static driver_t virtio_blk_driver = {
	"virtio_blk",
	virtio_blk_methods,
	sizeof(struct virtio_blk_softc),
};

static devclass_t virtio_blk_devclass;

DRIVER_MODULE(virtio_blk, virtiobus, virtio_blk_driver, virtio_blk_devclass, 0, 0);
MODULE_DEPEND(virtio_blk, virtiobus, 0, 0, 0);
