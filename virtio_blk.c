//problème de définition de sc_vq dans struct virtio_blk_softc;
//répercutions dans des appels de fonctions (pointer needed)

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

#include <sys/disk.h>
#include <sys/buf.h>
#include <sys/devicestat.h>

#include <sys/spinlock.h>
#include <sys/spinlock2.h>

#include <bus/pci/pcivar.h>
#include <bus/pci/pcireg.h>

#include "virtioreg.h"
#include "virtiovar.h"


/* Configuration registers */
#define VIRTIO_BLK_CONFIG_CAPACITY	0 /* 64bit */
#define VIRTIO_BLK_CONFIG_SIZE_MAX	8 /* 32bit */
#define VIRTIO_BLK_CONFIG_SEG_MAX	12 /* 32bit */
#define VIRTIO_BLK_CONFIG_GEOMETRY_C	16 /* 16bit */
#define VIRTIO_BLK_CONFIG_GEOMETRY_H	18 /* 8bit */
#define VIRTIO_BLK_CONFIG_GEOMETRY_S	19 /* 8bit */
#define VIRTIO_BLK_CONFIG_BLK_SIZE	20 /* 32bit */
#define VIRTIO_BLK_CONFIG_SECTORS_MAX	24 /* 32bit */

#define B_READ 1
/* Feature bits */
#define VIRTIO_BLK_F_BARRIER    (1<<0)
#define VIRTIO_BLK_F_SIZE_MAX   (1<<1)
#define VIRTIO_BLK_F_SEG_MAX    (1<<2)
#define VIRTIO_BLK_F_GEOMETRY   (1<<4)
#define VIRTIO_BLK_F_RO     (1<<5)
#define VIRTIO_BLK_F_BLK_SIZE   (1<<6)
#define VIRTIO_BLK_F_SCSI   (1<<7)
#define VIRTIO_BLK_F_FLUSH  (1<<9)
#define VIRTIO_BLK_F_SECTOR_MAX (1<<10)

/* Command */
#define VIRTIO_BLK_T_IN		0
#define VIRTIO_BLK_T_OUT	1
#define VIRTIO_BLK_T_BARRIER	0x80000000

/* Status */
#define VIRTIO_BLK_S_OK		0
#define VIRTIO_BLK_S_IOERR	1


/* Request header structure */
struct virtio_blk_req_hdr {
	uint32_t	type;	/* VIRTIO_BLK_T_* */
	uint32_t	ioprio;
	uint64_t	sector;
} __packed;
/* 512*virtio_blk_req_hdr.sector byte payload and 1 byte status follows */

/*
 * ld_virtiovar:
 */
struct virtio_blk_req {
	struct virtio_blk_req_hdr	vr_hdr;
	uint8_t 					vr_status;
	struct buf 				   *vr_bp;

    bus_dmamap_t cmd_dmap;
    bus_addr_t	ds_addr;	/* DMA address */
	bus_size_t	ds_len;		/* length of transfer */

	bus_dmamap_t	   payload_dmap;
    bus_dma_segment_t *segs;
    int 			   nseg;
};


struct virtio_blk_softc {

	//struct blk_softc sc_blk;
	device_t sc_dev;

	struct virtio_softc *sc_virtio;
	struct virtqueue sc_vq[1];

	struct virtio_blk_req	*sc_reqs;

	int sc_readonly;

	uint32_t    sc_features;
	int     maxxfersize;

	//added : what for ?
	bus_dma_segment_t	sc_reqs_segs[1];
	//kmutex_t	sc_lock;

    // Block stuff : for testing
    cdev_t cdev;
    struct devstat stats;
    struct disk disk;

};

static int  virtio_blk_probe(device_t dev);
static int  virtio_blk_attach(device_t dev);


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
	.d_strategy =  vbd_disk_strategy,
	.d_dump =      vbd_disk_dump,
} ;





/* Free descriptor management.
 */


static struct vq_entry * vq_alloc_entry(struct virtqueue *vq)
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


static void
map_payload(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct virtio_blk_req *vr = (struct virtio_blk_req *) arg;
	vr->segs = segs;
	vr->nseg = nseg;
	kprintf("%s, %p:%p addr:%lu, len:%lu\n",
			__FUNCTION__,segs,vr->segs,vr->segs[0].ds_addr, vr->segs[0].ds_len);
}

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

	r = virtio_enqueue_prep(sc->sc_virtio, vq, &slot);
	if (r != 0){
		kprintf("Bad bus_dmamap_load\n");
		return r;
	}
	kprintf("slot is %d\n", slot);

	vr = &sc->sc_reqs[slot];
	r = bus_dmamap_load(sc->sc_virtio->payloads_dmat,
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
	r = virtio_enqueue_reserve(sc->sc_virtio, vq, slot, vr->nseg + 2);
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
	
	bus_dmamap_sync(sc->sc_virtio->requests_dmat, vr->cmd_dmap,
			BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(sc->sc_virtio->payloads_dmat, vr->payload_dmap,
			isread?BUS_DMASYNC_PREREAD:BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(sc->sc_virtio->requests_dmat, vr->cmd_dmap,
			BUS_DMASYNC_PREREAD);

	 
	virtio_enqueue_p(sc->sc_virtio, vq, slot, vr->ds_addr, vr->ds_len, vr->cmd_dmap,
			 (bus_addr_t)0, sizeof(struct virtio_blk_req_hdr),
			 true);
	//BUS_SPACE UNRESTRICTED if no restriction
	virtio_enqueue(sc->sc_virtio, vq, slot, vr->segs, BUS_SPACE_UNRESTRICTED ,vr->payload_dmap, !isread);

	// il manque un argument (ds_addr ou ds_len)
	virtio_enqueue_p(sc->sc_virtio, vq, slot, vr->ds_addr, vr->ds_len, vr->cmd_dmap, offsetof(struct virtio_blk_req, vr_status), sizeof(uint8_t), false);
	virtio_enqueue_commit(sc->sc_virtio, vq, slot, true);
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

static void
ld_virtio_vq_done1(struct virtio_blk_softc *sc,
		   struct virtqueue *vq, int slot)
{
	struct virtio_blk_req *vr = &sc->sc_reqs[slot];
	struct buf *bp = vr->vr_bp;

	bus_dmamap_sync(sc->sc_virtio->requests_dmat, vr->cmd_dmap,
			//0, sizeof(struct virtio_blk_req_hdr),
			BUS_DMASYNC_POSTWRITE);
	bus_dmamap_sync(sc->sc_virtio->payloads_dmat, vr->payload_dmap,
	//		0, bp->b_bcount,
	(bp->b_cmd & BUF_CMD_READ)?BUS_DMASYNC_POSTREAD
					      :BUS_DMASYNC_POSTWRITE);
	bus_dmamap_sync(sc->sc_virtio->requests_dmat, vr->cmd_dmap,
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

	virtio_dequeue_commit(sc->sc_virtio, vq, slot);
	devstat_end_transaction_buf(&sc->stats, bp);
	kprintf("%s %d %p %p %c:%c\n",__FUNCTION__,  slot, (void *)&bp->b_bio_array[0],(void *)&bp->b_bio_array[1], bp->b_data[0],bp->b_data[511]);
	biodone(&bp->b_bio_array[1]);
	//lddone(&sc->sc_ld, bp);
}



static int
ld_virtio_vq_done(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct virtio_blk_softc *sc = device_get_softc(vsc->sc_child);
	int r = 0;
	int slot;

again:
	if (virtio_dequeue(vsc, vq, &slot, NULL))
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
	//struct blk_softc *blk = &sc->sc_blk;

	/*Create tag commands*/
	void * vaddr;
	int error,i;
	
	int allocsize = sizeof(struct virtio_blk_req) * qsize;
	//int payload_allocsize = 65536 * qsize;

	if (bus_dma_tag_create(sc->sc_virtio->virtio_dmat,
						   1,
						   0,
						   BUS_SPACE_MAXADDR,
						   BUS_SPACE_MAXADDR,
						   NULL, NULL,
						   allocsize,
						   1,
						   allocsize,
						   BUS_DMA_ALLOCNOW,
						   &sc->sc_virtio->requests_dmat) != 0) {
		kprintf("cmd_dmat tag create failed\n");
		return(1);
	}

	if (bus_dma_tag_create(sc->sc_virtio->virtio_dmat,
						   1,
						   0,
						   BUS_SPACE_MAXADDR,
						   BUS_SPACE_MAXADDR,
						   NULL, NULL,
						   BUS_SPACE_MAXSIZE_24BIT,
						   30,
						   BUS_SPACE_MAXSIZE_24BIT,
						   BUS_DMA_ALIGNED,
						   &sc->sc_virtio->payloads_dmat) != 0) {
		kprintf("cmd_dmat tag create failed\n");
		return(1);
	}
  
	if (bus_dmamem_alloc(sc->sc_virtio->requests_dmat, (void **)&vaddr,
					 BUS_DMA_NOWAIT,&sc->sc_virtio->cmds_dmamap)) {
		kprintf("bus_dmammem_load bad");
		return(ENOMEM);
	}

	if (bus_dmamap_load(sc->sc_virtio->requests_dmat,
							sc->sc_virtio->cmds_dmamap,
							vaddr,
							allocsize, 
							virtio_cmds_helper, sc->sc_virtio, BUS_DMA_NOWAIT) != 0) {
			kprintf("bus_dmamap_load bad");
			return 1;
	}
	sc->sc_reqs = vaddr;
	kprintf("vaddr:%p, qsize:%d\n", vaddr,qsize);
	for (i = 0; i< qsize; i++) { 
		struct virtio_blk_req *vr = &sc->sc_reqs[i];
		

		error = bus_dmamap_create(sc->sc_virtio->requests_dmat,BUS_DMA_NOWAIT, &vr->cmd_dmap);
		if (error) {
			kprintf("bus_dmamap_create error\n");
			return 1;
		}
		
		if (bus_dmamap_load(sc->sc_virtio->requests_dmat,
							vr->cmd_dmap, 
							&vr->vr_hdr,
							24,//offsetof(struct virtio_blk_req, vr_bp),
							virtio_cmd_helper, vr, 0/*BUS_DMA_NOWAIT*/) != 0) {
			kprintf("bus_dmamap_load bad");
			return 1;
		}
		//kprintf("i:%d %p vr:%u %u \n",i,vr, vr->ds_len, &vr->vr_hdr);

		error = bus_dmamap_create(sc->sc_virtio->payloads_dmat, 0, &vr->payload_dmap);
		if (error) {
			kprintf("bus_dmamap_create error\n");
			return 1;
		}
		
	}
	kprintf("%s done\n", __FUNCTION__);


	return 0;
}

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

static int virtio_blk_attach(device_t dev)
{
	// dev is the child device

	struct virtio_blk_softc *sc = device_get_softc(dev);
	// blk_softc *blk = &sc->sc_blk;
	sc->sc_dev = dev;

	device_t pdev = device_get_parent(sc->sc_dev);
	struct virtio_softc *vsc = device_get_softc(pdev);

	sc->sc_virtio = vsc;
	vsc->dev = pdev;

	// need to add this line ?
	// warning at compilation -> unused
	//struct virtqueue *vq = &sc->sc_vq;

	struct resource *io;
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
	vsc->sc_iot = rman_get_bustag(io);
	vsc->sc_ioh = rman_get_bushandle(io);
    vsc->sc_config_offset = VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI;
	vsc->sc_config_change = 0;
	vsc->sc_intrhand = virtio_vq_intr;

	kprintf("%u %u\n", (unsigned int) vsc->sc_iot,(unsigned int)vsc->sc_ioh);
	kprintf("%d Virtio %s Device (rev. 0x%02x)\n",
			pci_get_vendor(dev),
			(pci_read_config(dev, PCIR_SUBDEV_0, 2)<NDEVNAMES?
			 virtio_device_name[pci_read_config(dev, PCIR_SUBDEV_0, 2)]:"Unknown"),
			pci_read_config(dev, PCIR_REVID, 1));

	vsc->res_irq = bus_alloc_resource_any(vsc->dev, SYS_RES_IRQ,
			&vsc->rid_irq, RF_SHAREABLE|RF_ACTIVE);
	kprintf("rid_irq:%d\n", vsc->rid_irq);
	if (vsc->res_irq == NULL){
		kprintf("Couldn't alloc res_irq\n");
	}

	error = bus_setup_intr(vsc->dev, vsc->res_irq, 0,
			(driver_intr_t *)vsc->virtio_intr, (void *)vsc,
			&(vsc->virtio_intr), NULL);

	if (error){
		kprintf("Couldn't setup intr\n");
		return(1);
	}

	virtio_reset(vsc);
	virtio_set_status(vsc, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	virtio_set_status(vsc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);
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
			&vsc->virtio_dmat);

	if (error ) {
		kprintf("error");
		return 1;
	}

 	virtio_set_status(vsc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);

	/*Block attach stuff*/
    device_set_desc(dev, "virtio-blk");

	features = virtio_negotiate_features(vsc,
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
			virtio_read_device_config_4(vsc, VIRTIO_BLK_CONFIG_SECTORS_MAX)	* 512;
		kprintf("read_device_config maxxfersize:%u\n",sc->maxxfersize);
		if (sc->maxxfersize > MAXPHYS)
			sc->maxxfersize = MAXPHYS;
	}
	kprintf("maxxfersize:%d\n", sc->maxxfersize);

	if (virtio_alloc_vq(vsc, sc->sc_vq, 0,
			    sc->maxxfersize, sc->maxxfersize / NBPG + 2,
			    "I/O request") != 0) {
		kprintf("Bad virtio_alloc_vq\n");
		return 1;
	
	}

	qsize = sc->sc_vq[1].vq_num;
	sc->sc_vq[1].vq_done = ld_virtio_vq_done(sc->sc_vq[1]);

	/* construct the disk_info */
    bzero(&info, sizeof(info));

	kprintf("Size is %llu\n",(unsigned long long)
			virtio_read_device_config_8(vsc, VIRTIO_BLK_CONFIG_CAPACITY));

	if (features & VIRTIO_BLK_F_BLK_SIZE) {
		kprintf("BLKSIZE feature is %d \n",
				virtio_read_device_config_4(vsc,VIRTIO_BLK_CONFIG_BLK_SIZE));
		//info.d_secsize = virtio_read_device_config_4(vsc,
			//		VIRTIO_BLK_CONFIG_BLK_SIZE);
	}

	info.d_media_blksize = DEV_BSIZE;
	info.d_media_blocks =  
		virtio_read_device_config_8(vsc, VIRTIO_BLK_CONFIG_CAPACITY);
	kprintf("Media blocks is %lu\n", info.d_media_blocks);
	if (features & VIRTIO_BLK_F_GEOMETRY) {		


		info.d_ncylinders = virtio_read_device_config_2(vsc,
					VIRTIO_BLK_CONFIG_GEOMETRY_C);
		info.d_nheads     = virtio_read_device_config_1(vsc,
					VIRTIO_BLK_CONFIG_GEOMETRY_H);
		info.d_secpertrack = virtio_read_device_config_1(vsc,
					VIRTIO_BLK_CONFIG_GEOMETRY_S);

		info.d_secpercyl = info.d_secpertrack * info.d_nheads;

		kprintf("c:%u h:%u s:%u\n",
				virtio_read_device_config_2(vsc, VIRTIO_BLK_CONFIG_GEOMETRY_C),
				virtio_read_device_config_1(vsc, VIRTIO_BLK_CONFIG_GEOMETRY_H),
				virtio_read_device_config_1(vsc, VIRTIO_BLK_CONFIG_GEOMETRY_S));
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

	if ( ld_virtio_alloc_reqs(sc, qsize) < 0)
		goto err;


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

err:
	vsc->sc_child = (void*)1;
	return 0;
}

static int virtio_blk_detach(device_t dev)
{
	kprintf("%s \n",__FUNCTION__);
	struct virtio_blk_softc *sc = device_get_softc(dev);
	device_t pdev = device_get_parent(sc->sc_dev);
	struct virtio_softc *vsc = device_get_softc(pdev);
	struct virtqueue *vq = &sc->sc_vq;
	int i;

	for (i=0; i<sc->sc_vq[1].vq_num; i++) {
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
	virtio_free_vq(vsc, &sc->sc_vq[1]);

	/*unload and free virtqueue*/
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
//	DEVMETHOD(device_identify,         virtio_identify),
	DEVMETHOD(device_probe,         virtio_blk_probe),
	DEVMETHOD(device_attach,        virtio_blk_attach),
	DEVMETHOD(device_detach,		virtio_blk_detach),
//	DEVMETHOD(bus_driver_added,    virtio_bus_driver_added),
//  DEVMETHOD(bus_add_child,    virtio_bus_add_child),

	{ 0, 0 }
};


static driver_t virtio_blk_driver = {
//	"virtiobus",
	"virtio_blk",
		virtio_blk_methods,
	sizeof(struct virtio_blk_softc),
};

static devclass_t virtio_blk_devclass;

DRIVER_MODULE(virtio_blk, pci, virtio_blk_driver, virtio_blk_devclass, 0, 0);
MODULE_VERSION(virtio_blk, 0);
