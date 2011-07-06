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

/* Configuration registers */
#define VIRTIO_BALLOON_CONFIG_NUM_PAGES	0 /* 32bit */
#define VIRTIO_BALLOON_CONFIG_ACTUAL	4 /* 32bit */

/* Feature bits */
#define VIRTIO_BALLOON_F_MUST_TELL_HOST (1<<0)
#define VIRTIO_BALLOON_F_STATS_VQ	(1<<1)

#define PGS_PER_REQ		(256) /* 1MB, 4KB/page */

CTASSERT((PAGE_SIZE) == (VIRTIO_PAGE_SIZE)); /* XXX */

struct balloon_req {
	bus_dmamap_t bl_dmamap;
	struct pglist bl_pglist;
	int	bl_nentries;
	uint32_t bl_pages[PGS_PER_REQ];
};

struct viomb_softc {

	device_t sc_dev;

	struct virtio_softc	*sc_virtio;
	struct virtqueue sc_vq[2];

	unsigned int sc_npages;
	unsigned int sc_actual;
	int	sc_inflight;
	struct balloon_req	sc_req;
	struct pglist sc_balloon_pages;

	int	sc_inflate_done;
	int	sc_deflate_done;

	struct cv *sc_wait;
	struct spinlock	*sc_waitlock;
};

static int	balloon_initialized = 0; /* multiple balloon is not allowed */

static int	viomb_match(device_t, cfdata_t, void *);
static void	viomb_attach(device_t, device_t, void *);
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

static int
viomb_match(device_t dev){
	return 0;
}


static void
viomb_read_config(struct viomb_softc *sc)
{

}


/*
 * Config change callback: wakeup the kthread.
 */
static int
viomb_config_change(struct virtio_softc *vsc)
{
	rturn 0;
}


static int
inflateq_done(struct virtqueue *vq)
{
	return 0;
}


/*
 * Inflate: consume some amount of physical memory.
 */
static int
inflate(struct viomb_softc *sc)
{
	return 0;
}


static int
inflate_done(struct viomb_softc *sc)
{
	return 0;
}


/*
 * Deflate: free previously allocated memory.
 */
static int
deflate(struct viomb_softc *sc)
{
	return 0;
}


static int
deflateq_done(struct virtqueue *vq)
{
	return 0;
}


static int
deflate_done(struct viomb_softc *sc)
{
	return 0;
}


/*
 * Kthread: sleeps, eventually inflate and deflate.
 */
static void
viomb_thread(void *arg)
{

}


static void
viomb_attach(device_t dev)
{
	return;
}

static void
viomb_detach();







static device_method_t virtio_mb_methods[] = {
	DEVMETHOD(device_probe,		virtio_mb_probe),
	DEVMETHOD(device_attach,	virtio_mb_attach),
	DEVMETHOD(device_detach,	virtio_mb_detach),
	{ 0, 0 }
};

static driver_t virtio_mb_driver = {
	"virtio_mb",
	virtio_mb_methods,
	sizeof(struct virtio_blk_softc),
};

static devclass_t virtio_mb_devclass;

DRIVER_MODULE(virtio_mb, virtiobus, virtio_mb_driver, virtio_mb_devclass, 0, 0);
MODULE_DEPEND(virtio_mb, virtiobus, 0, 0, 0);
