// sysctl node; mstohz;

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
#include <sys/condvar.h>
#include <sys/spinlock.h>
#include <sys/spinlock2.h>
#include <bus/pci/pcivar.h>
#include <bus/pci/pcireg.h>
#include <sys/endian.h>
#include <sys/types.h>
#include <sys/kthread.h>
#include <sys/serialize.h>
#include <sys/msgport.h>
#include <sys/msgport2.h>
#include <sys/mplock2.h>
#include <vm/vm_extern.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/_timeval.h>
#include <sys/time.h>


#include "virtiovar.h"
#include "virtioreg.h"

/* Configuration registers */
#define VIRTIO_BALLOON_CONFIG_NUM_PAGES	0 /* 32bit */
#define VIRTIO_BALLOON_CONFIG_ACTUAL	4 /* 32bit */

/* Feature bits */
#define VIRTIO_BALLOON_F_MUST_TELL_HOST (1<<0)
#define VIRTIO_BALLOON_F_STATS_VQ		(1<<1)

#define PGS_PER_REQ		(256) /* 1MB, 4KB/page */

CTASSERT((PAGE_SIZE) == (VIRTIO_PAGE_SIZE)); /* XXX */

#define INFL_VQ 0
#define DEFL_VQ 1

struct balloon_req {
	bus_dmamap_t 		bl_dmamap;
	int 				bl_dmamap_nseg;
	bus_dma_segment_t	*bl_dmamap_segment;
	struct pglist 		bl_pglist;
	int					bl_nentries;
	uint32_t 			bl_pages[PGS_PER_REQ];
};

struct viomb_softc {

	device_t 			sc_dev;

	struct virtio_softc	*sc_virtio;
	struct virtqueue 	sc_vq[2]; /* inflate queue, deflate queue - no stats queue	 */

	unsigned int 		sc_npages;
	unsigned int		sc_actual;
	int					sc_inflight;
	struct balloon_req	sc_req;
	struct pglist 		sc_balloon_pages;

	int					sc_inflate_done;
	int					sc_deflate_done;

	struct cv 			sc_wait;
	struct lock			sc_waitlock;

	struct lwkt_msg		sc_lmsg;
	struct lwkt_port 	sc_port;
	struct thread 		*sc_viomb_td;

	int 				sc_nseg_temp;
	bus_dma_segment_t	*sc_segment_temp;

};

static int	balloon_initialized = 0; /* multiple balloon is not allowed */

static int	viomb_probe(device_t);
static void	viomb_attach(device_t);
static void viomb_detach(device_t);
static int vioif_destroy_vq(struct viomb_softc *, struct virtio_softc *, int);
static void	viomb_read_config(struct viomb_softc *);
static int	viomb_config_change(struct virtio_softc *);
static int	inflate(struct viomb_softc *);
static int	inflateq_done(struct virtqueue *);
static int	inflate_done(struct viomb_softc *);
static int	deflate(struct viomb_softc *);
static int	deflateq_done(struct virtqueue *);
static int	deflate_done(struct viomb_softc *);
static void	viomb_thread(void *);

//CFATTACH_DECL_NEW(viomb, sizeof(struct viomb_softc), viomb_match, viomb_attach, NULL, NULL);

static void
bl_callback(void *callback_arg, bus_dma_segment_t *segs, int nseg, int error)
{

	debug("callback is called\n");
	struct viomb_softc *sc = (struct viomb_softc *) callback_arg;

	debug("sc affectation is okay\n");

	if (error != 0){
		debug("error %u in rxhdr_load_callback\n", error);
		return;
	}

	sc->sc_nseg_temp = nseg;
	sc->sc_segment_temp = segs;

	return;
}

static int
//viomb_match(device_t dev, struct cfdata_t match , void *aux){
viomb_probe(device_t dev)
{

	device_t pdev = device_get_parent(dev);

	if(pci_read_config(pdev,PCIR_SUBDEV_0,2) == PCI_PRODUCT_VIRTIO_BALLOON) {
		debug("parent:%p is net\n", pdev);
	} else {
		debug("parent:%p is not net\n", pdev);
		return 1;
	}

	return 0;
}


static void
viomb_read_config(struct viomb_softc *sc)
{
	unsigned int reg;

	/* these values are explicitly specified as little-endian */
	reg = virtio_read_device_config_4(sc->sc_virtio,
			VIRTIO_BALLOON_CONFIG_NUM_PAGES);
	sc->sc_npages = le32toh(reg);

	reg = virtio_read_device_config_4(sc->sc_virtio,
			VIRTIO_BALLOON_CONFIG_ACTUAL);
	sc->sc_actual = le32toh(reg);
}


/*
 * Config change callback: wakeup the kthread.
 */
static int
viomb_config_change(struct virtio_softc *vsc)
{
	struct viomb_softc *sc = device_get_softc(vsc->sc_child);
	unsigned int old;

	old = sc->sc_npages;
	viomb_read_config(sc);
	lockmgr(&sc->sc_waitlock, LK_EXCLUSIVE);
	cv_signal(&sc->sc_wait);
	lockmgr(&sc->sc_waitlock, LK_RELEASE);
	if (sc->sc_npages > old)
		debug("inflating balloon from %u to %u.\n",
		       old, sc->sc_npages);
	else if  (sc->sc_npages < old)
		debug("deflating balloon from %u to %u.\n",
		       old, sc->sc_npages);

	return 1;
}


/*
 * Inflate: consume some amount of physical memory.
 */

/* called from viomb thread */
static int
inflate(struct viomb_softc *sc)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	int i, slot;
	int *r;
	uint64_t nvpages, nhpages;
	struct balloon_req *b;
	struct vm_page *p;
	struct virtqueue *vq = &sc->sc_vq[INFL_VQ];

	if (sc->sc_inflight)
		return 0;
	nvpages = sc->sc_npages - sc->sc_actual;
	if (nvpages > PGS_PER_REQ)
		nvpages = PGS_PER_REQ;
	nhpages = nvpages * VIRTIO_PAGE_SIZE / PAGE_SIZE;

	b = &sc->sc_req;

	r = contigmalloc(nhpages*PAGE_SIZE, M_DEVBUF, 0, 0, UINT32_MAX*PAGE_SIZE, 0, 0);

	if (r != NULL){
		debug("%llu pages of physical memory "
		       "could not be allocated, retrying...\n",nhpages);
		return 1;	/* sleep longer */
	}

	b->bl_nentries = nvpages;
	i = 0;

	TAILQ_FOREACH(p,
			&b->bl_pglist,
			pageq ){
			//pageq.queue) {
	b->bl_pages[i++] = p->phys_addr / VIRTIO_PAGE_SIZE;
	}
	KKASSERT(i == nvpages);

	//after callback function and bus_dmamap_load in viomb_attach
	b->bl_dmamap_nseg = sc->sc_nseg_temp;
	b->bl_dmamap_segment = sc->sc_segment_temp;

	if (virtio_enqueue_prep(vsc, vq, &slot) != 0) {
		debug("inflate enqueue failed.\n");
		contigfree(&b->bl_pglist, nhpages*PAGE_SIZE, M_DEVBUF);
		return 0;
	}

	if (virtio_enqueue_reserve(vsc, vq, slot, 1)) {
		debug("inflate enqueue failed.\n");
		contigfree(&b->bl_pglist, nhpages*PAGE_SIZE, M_DEVBUF);

		return 0;
	}

	bus_dmamap_sync(vsc->requests_dmat, b->bl_dmamap, BUS_DMASYNC_PREWRITE);
	virtio_enqueue(vsc, vq, slot, b->bl_dmamap_segment, b->bl_dmamap_nseg, b->bl_dmamap, true );
	virtio_enqueue_commit(vsc, vq, slot, true);
	sc->sc_inflight += nvpages;

	return 0;
}


static int
inflateq_done(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct viomb_softc *sc = device_get_softc(vsc->sc_child);

	lockmgr(&sc->sc_waitlock, LK_EXCLUSIVE);
	sc->sc_inflate_done = 1;
	cv_signal(&sc->sc_wait);
	lockmgr(&sc->sc_waitlock, LK_RELEASE);

	return 1;
}


static int
inflate_done(struct viomb_softc *sc)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = &sc->sc_vq[INFL_VQ];
	struct balloon_req *b;
	int r, slot;
	uint64_t nvpages;
	struct vm_page *p;

	r = virtio_dequeue(vsc, vq, &slot, NULL);
	if (r != 0) {
		debug("inflate dequeue failed, errno %d.\n", r);
		return 1;
	}

	virtio_dequeue_commit(vsc, vq, slot);

	b = &sc->sc_req;
	nvpages = b->bl_nentries;
	bus_dmamap_sync(vsc->requests_dmat, b->bl_dmamap, BUS_DMASYNC_POSTWRITE);
	while (!TAILQ_EMPTY(&b->bl_pglist)) {
		p = TAILQ_FIRST(&b->bl_pglist);
		TAILQ_REMOVE(&b->bl_pglist, p, pageq);
		TAILQ_INSERT_TAIL(&sc->sc_balloon_pages, p, pageq);
	}

	sc->sc_inflight -= nvpages;
	bus_space_write_4(vsc->sc_iot, vsc->sc_ioh,
				     VIRTIO_BALLOON_CONFIG_ACTUAL,
				     sc->sc_actual + nvpages);
	viomb_read_config(sc);

	return 1;
}


/*
 * Deflate: free previously allocated memory.
 */
static int
deflate(struct viomb_softc *sc)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	int i, slot;
	uint64_t nvpages, nhpages;
	struct balloon_req *b;
	struct vm_page *p;
	struct virtqueue *vq = &sc->sc_vq[DEFL_VQ];

	nvpages = (sc->sc_actual + sc->sc_inflight) - sc->sc_npages;

	if (nvpages > PGS_PER_REQ)
		nvpages = PGS_PER_REQ;

	nhpages = nvpages * VIRTIO_PAGE_SIZE / PAGE_SIZE;

	b = &sc->sc_req;
	b->bl_nentries = nvpages;
	TAILQ_INIT(&b->bl_pglist);
	for (i = 0; i < nhpages; i++) {
		p = TAILQ_FIRST(&sc->sc_balloon_pages);
		TAILQ_REMOVE(&sc->sc_balloon_pages, p, pageq);
		TAILQ_INSERT_TAIL(&b->bl_pglist, p, pageq);
		b->bl_pages[i] = p->phys_addr / VIRTIO_PAGE_SIZE;
	}

	if (virtio_enqueue_prep(vsc, vq, &slot) != 0) {
		debug("deflate enqueue failed.\n");
		TAILQ_FOREACH_REVERSE(p, &b->bl_pglist, pglist, pageq) {
			TAILQ_REMOVE(&b->bl_pglist, p, pageq);
			TAILQ_INSERT_HEAD(&sc->sc_balloon_pages, p, pageq);
		}
		return 0;
	}

	if (virtio_enqueue_reserve(vsc, vq, slot, 1) != 0) {
		debug("deflate enqueue failed.\n");
		TAILQ_FOREACH_REVERSE(p, &b->bl_pglist, pglist, pageq) {
			TAILQ_REMOVE(&b->bl_pglist, p, pageq);
			TAILQ_INSERT_HEAD(&sc->sc_balloon_pages, p, pageq);
		}
		return 0;
	}

	bus_dmamap_sync(vsc->requests_dmat, b->bl_dmamap, BUS_DMASYNC_PREWRITE);
	virtio_enqueue(vsc, vq, slot, b->bl_dmamap_segment, b->bl_dmamap_nseg, b->bl_dmamap, true);
	virtio_enqueue_commit(vsc, vq, slot, true);
	sc->sc_inflight -= nvpages;

	if (!(vsc->sc_features & VIRTIO_BALLOON_F_MUST_TELL_HOST))
		contigfree(&b->bl_pglist, nhpages*PAGE_SIZE, M_DEVBUF);

	return 0;

}


static int
deflateq_done(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct viomb_softc *sc = device_get_softc(vsc->sc_child);

	lockmgr(&sc->sc_waitlock, LK_EXCLUSIVE);
	sc->sc_deflate_done = 1;
	cv_signal(&sc->sc_wait);
	lockmgr(&sc->sc_waitlock, LK_RELEASE);

	return 1;

}


static int
deflate_done(struct viomb_softc *sc)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = &sc->sc_vq[DEFL_VQ];
	struct balloon_req *b;
	int r, slot;
	uint64_t nvpages, nhpages;

	r = virtio_dequeue(vsc, vq, &slot, NULL);

	if (r != 0) {
		debug("deflate dequeue failed, errno %d\n", r);
		return 1;
	}
	virtio_dequeue_commit(vsc, vq, slot);

	b = &sc->sc_req;
	nvpages = b->bl_nentries;
	nhpages = nvpages * VIRTIO_PAGE_SIZE / PAGE_SIZE;
	bus_dmamap_sync(vsc->requests_dmat, b->bl_dmamap, BUS_DMASYNC_POSTWRITE);

	if (vsc->sc_features & VIRTIO_BALLOON_F_MUST_TELL_HOST)
		contigfree(&b->bl_pglist, nhpages*PAGE_SIZE, M_DEVBUF);

	sc->sc_inflight += nvpages;
	bus_space_write_4(vsc->sc_iot, vsc->sc_ioh,
				     VIRTIO_BALLOON_CONFIG_ACTUAL,
				     sc->sc_actual - nvpages);
	viomb_read_config(sc);

	return 1;



}


/*
 * Kthread: sleeps, eventually inflate and deflate.
 * values of sleeptime ?
 */
static void
viomb_thread(void *arg)
{
	struct viomb_softc *sc = arg;
	int r;
	struct timeval sleeptime;

	sleeptime.tv_usec = 0;

	while(1){

		sleeptime.tv_sec = 30000;
		if (sc->sc_npages > sc->sc_actual + sc->sc_inflight){

			if (sc->sc_inflight == 0) {
				r = inflate(sc);
				if (r != 0)
					sleeptime.tv_sec = 10000;
				else
					sleeptime.tv_sec = 1000;
			} else
				sleeptime.tv_sec = 100;
		} else if (sc->sc_npages < sc->sc_actual + sc->sc_inflight) {
			if (sc->sc_inflight == 0)
				r = deflate(sc);
			sleeptime.tv_sec = 100;
		}

	again:
		lockmgr(&sc->sc_waitlock, LK_EXCLUSIVE);

		if(sc->sc_inflate_done){

			sc->sc_inflate_done = 0;
			lockmgr(&sc->sc_waitlock, LK_RELEASE);
			inflate_done(sc);
			goto again;
		}

		if (sc->sc_deflate_done){

			sc->sc_deflate_done = 0;
			lockmgr(&sc->sc_waitlock, LK_RELEASE);
			deflate_done(sc);
			goto again;
		}

		//mstohz function: milliseconds to clock ticks
		//The process/thread will sleep at most timo / hz seconds
		cv_timedwait(&sc->sc_wait, &sc->sc_waitlock, tvtohz_low(&sleeptime));
		lockmgr(&sc->sc_waitlock, LK_RELEASE);
	}
}


static void
viomb_attach(device_t dev)
{
	struct viomb_softc *sc = device_get_softc(dev);
	device_t pdev = device_get_parent(dev);
	struct virtio_softc *vsc = device_get_softc(pdev);
	const struct sysctlnode *node;
	int r;

	if (vsc->sc_child != NULL) {
		debug("child already attached for "
			"something wrong...\n");
		return;
	}

	if (balloon_initialized++) {
		debug("balloon already exists; something wrong...\n");
		goto err;
	}

	sc->sc_dev = dev;
	sc->sc_virtio = vsc;

	vsc->sc_child = dev;
	//vsc->sc_ipl = IPL_VM;
	vsc->sc_vqs = &sc->sc_vq[INFL_VQ]; /* inflate queue */
	vsc->sc_nvqs = 2; /* no stats queue */
	vsc->sc_config_change = viomb_config_change;
	//vsc->sc_intrhand = virtio_vq_intr; by default

	virtio_negotiate_features(vsc, VIRTIO_CONFIG_DEVICE_FEATURES);

	/* Allocate the queues */
	if ((virtio_alloc_vq(vsc, &sc->sc_vq[INFL_VQ], 0,
			sizeof(uint32_t)*PGS_PER_REQ, 1, "inflate") != 0) ||
	    (virtio_alloc_vq(vsc, &sc->sc_vq[DEFL_VQ], 1,
			     sizeof(uint32_t)*PGS_PER_REQ, 1,"deflate") != 0)) {
		goto err;
	}
	sc->sc_vq[INFL_VQ].vq_done = inflateq_done;
	sc->sc_vq[DEFL_VQ].vq_done = deflateq_done;

	viomb_read_config(sc);
	sc->sc_inflight = 0;
	TAILQ_INIT(&sc->sc_balloon_pages);

	r = bus_dmamap_create(vsc->requests_dmat, BUS_DMA_NOWAIT, &sc->sc_req.bl_dmamap);

	if (r != 0 ){
		debug("dmamap creation failed.\n");
		goto err;
	}

	r = bus_dmamap_load(vsc->requests_dmat,
			sc->sc_req.bl_dmamap,
			sc->sc_req.bl_pages[INFL_VQ],
			sizeof(uint32_t) * PGS_PER_REQ,
			bl_callback,
			sc,
			0);

	if (r != 0 ){
		debug("dmamap creation failed.\n");
		goto err;
	}

	sc->sc_inflate_done = 0;
	sc->sc_deflate_done = 0;

	lockinit(&sc->sc_waitlock, "waitlock", 0, 0);
	cv_init(&sc->sc_wait, "sc_wait");

	r = lwkt_create(viomb_thread,
			sc->sc_dev,
			&sc->sc_viomb_td,
			NULL, 0, 0,
			"viomb thread");

	if (r){
		debug("Creation of viomb_thread failed\n");
		goto err;
	}

	/* add nodes */
	//sysctl_createv()


err:
	debug("attach failure");
	if (vsc->sc_nvqs == 2){
		virtio_free_vq(vsc, &sc->sc_vq[DEFL_VQ]);
		cv_destroy(&sc->sc_wait);
		lockuninit(&sc->sc_waitlock);
		bus_dmamap_destroy(vsc->requests_dmat, sc->sc_req.bl_dmamap);
		vsc->sc_nvqs = 1;
	}
	if (vsc->sc_nvqs == 1) {
		virtio_free_vq(vsc, &sc->sc_vq[INFL_VQ]);
		vsc->sc_nvqs = 0;
	}
	vsc->sc_child = (void*)1;
	return ;
}


static void
viomb_detach(device_t dev)
{

	kprintf("%s \n",__FUNCTION__);
	struct viomb_softc *sc = device_get_softc(dev);
	device_t pdev = device_get_parent(sc->sc_dev);
	struct virtio_softc *vsc = device_get_softc(pdev);
	int i;

	cv_destroy(&sc->sc_wait);
	lockuninit(&sc->sc_waitlock);

	bus_dmamap_destroy(vsc->requests_dmat, sc->sc_req.bl_dmamap);

	bus_dma_tag_destroy(vsc->requests_dmat);

	virtio_reset(vsc);
	virtio_free_vq(vsc, &vsc->sc_vqs[INFL_VQ]);
	virtio_free_vq(vsc, &vsc->sc_vqs[DEFL_VQ]);

	vioif_destroy_vq(sc, vsc, INFL_VQ); /* destroy inflate vq */
	vioif_destroy_vq(sc, vsc, DEFL_VQ); /* destroy deflate vq */




	/* destroy nodes */
	//sysctl_destroyv;
	return;
}


/* Unload and free &sc->sc_vq[numq] */
static int
vioif_destroy_vq( struct viomb_softc *sc, struct virtio_softc *vsc, int numq){

	struct virtqueue *vq = &vsc->sc_vqs[numq];
	int i;

	kfree(vq->vq_entries, M_DEVBUF);
	bus_dmamap_unload(vq->vq_dmat, vq->vq_dmamap);
	bus_dmamem_free(vq->vq_dmat, vq->vq_vaddr, vq->vq_dmamap);
	bus_dma_tag_destroy(vq->vq_dmat);
	memset(vq, 0, sizeof(*vq));

	return 0;
}



static device_method_t virtio_mb_methods[] = {
	DEVMETHOD(device_probe,		viomb_probe),
	DEVMETHOD(device_attach,	viomb_attach),
	DEVMETHOD(device_detach,	viomb_detach),
	{ 0, 0 }
};

static driver_t virtio_mb_driver = {
	"virtio_mb",
	virtio_mb_methods,
	sizeof(struct viomb_softc),
};

static devclass_t virtio_mb_devclass;

DRIVER_MODULE(virtio_mb, virtiobus, virtio_mb_driver, virtio_mb_devclass, 0, 0);
MODULE_DEPEND(virtio_mb, virtiobus, 0, 0, 0);
