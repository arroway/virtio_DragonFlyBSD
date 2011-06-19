/*
 * written: probe, attach
 * to be tested: probe, attach
 *
 * current: detach (entirely created)
 * next: vioif_rx_vq_done, vioif_tx_vq_done, vioif_ctrl_vq_done
 * virtio_start_vq_intr, virtio_stop_vq_intr, vioif_deferred_init
 * ifnet functions
 *
 * check if_attach and ether_ifattach
 *
 * */




/* $NetBSD$	*/

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
#include <sys/mutex2.h>
#include <sys/sockio.h>
#include <sys/resource.h>
#include <sys/types.h>

#include <bus/pci/pcivar.h>
#include <bus/pci/pcireg.h>
#include <sys/taskqueue.h>

#include <net/ethernet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ifq_var.h>

#include <sys/spinlock.h>
#include <sys/spinlock2.h>

#include "virtiovar.h"
#include "virtioreg.h"

#define ether_sprintf(x) "<dummy>"
/*
 * if_vioifreg.h:
 */
/* Configuration registers */
#define VIRTIO_NET_CONFIG_MAC		0 /* 8bit x 6byte */
#define VIRTIO_NET_CONFIG_STATUS	6 /* 16bit */

/* Feature bits */
#define VIRTIO_NET_F_CSUM	(1<<0)
#define VIRTIO_NET_F_GUEST_CSUM	(1<<1)
#define VIRTIO_NET_F_MAC	(1<<5)
#define VIRTIO_NET_F_GSO	(1<<6)
#define VIRTIO_NET_F_GUEST_TSO4	(1<<7)
#define VIRTIO_NET_F_GUEST_TSO6	(1<<8)
#define VIRTIO_NET_F_GUEST_ECN	(1<<9)
#define VIRTIO_NET_F_GUEST_UFO	(1<<10)
#define VIRTIO_NET_F_HOST_TSO4	(1<<11)
#define VIRTIO_NET_F_HOST_TSO6	(1<<12)
#define VIRTIO_NET_F_HOST_ECN	(1<<13)
#define VIRTIO_NET_F_HOST_UFO	(1<<14)
#define VIRTIO_NET_F_MRG_RXBUF	(1<<15)
#define VIRTIO_NET_F_STATUS	(1<<16)
#define VIRTIO_NET_F_CTRL_VQ	(1<<17)
#define VIRTIO_NET_F_CTRL_RX	(1<<18)
#define VIRTIO_NET_F_CTRL_VLAN	(1<<19)

/* Status */
#define VIRTIO_NET_S_LINK_UP	1

/* Header Flags */
#define VIRTIO_NET_HDR_F_NEEDS_CSUM	1 /* flags */
#define VIRTIO_NET_HDR_GSO_NONE		0 /* gso_type */
#define VIRTIO_NET_HDR_GSO_TCPV4	1 /* gso_type */
#define VIRTIO_NET_HDR_GSO_UDP		3 /* gso_type */
#define VIRTIO_NET_HDR_GSO_TCPV6	4 /* gso_type */
#define VIRTIO_NET_HDR_GSO_ECN		0x80 /* gso_type, |'ed */

#define VIRTIO_NET_MAX_GSO_LEN		(65536+ETHER_HDR_LEN)

#define RX_VQ 0
#define TX_VQ 1
#define CTRL_VQ 2

#define NDEVNAMES	(sizeof(virtio_device_name)/sizeof(char*))
#define MINSEG_INDIRECT     2 /* use indirect if nsegs >= this value */

struct virtio_net_hdr {

	uint8_t		flags;
	uint8_t 	gso_type;
	uint16_t	hdr_len;
	uint16_t	gso_size;
	uint16_t	csum_start;
	uint16_t	csum_offset;

#if 0
	uint16_t	num_buffers;	/* if VIRTIO_NET_F_MRG_RXBUF enabled */
#endif

}__packed;

struct virtio_net_softc {
	device_t		dev;
	struct virtio_softc *sc_virtio;
	struct virtqueue sc_vq[3];
	int sc_readonly;
	uint32_t    sc_features;
	int     maxxfersize;
	short			sc_ifflags;

	/* net specific */
	short sc_ifflags;
	uint8_t sc_mac[ETHER_ADDR_LEN];
	struct ethercom	sc_ethercom;



	bus_dma_segment_t	sc_hdr_segs[1];
		struct virtio_net_hdr	*sc_hdrs;
	#define sc_rx_hdrs	sc_hdrs
		struct virtio_net_hdr	*sc_tx_hdrs;
		struct virtio_net_ctrl_cmd *sc_ctrl_cmd;
		struct virtio_net_ctrl_status *sc_ctrl_status;
		struct virtio_net_ctrl_rx *sc_ctrl_rx;
		struct virtio_net_ctrl_mac_tbl *sc_ctrl_mac_tbl_uc;
		struct virtio_net_ctrl_mac_tbl *sc_ctrl_mac_tbl_mc;

		/* kmem */
		bus_dmamap_t		*sc_arrays;
    #define sc_rxhdr_dmamaps sc_arrays
		bus_dmamap_t		*sc_txhdr_dmamaps;
		bus_dmamap_t		*sc_rx_dmamaps;
		bus_dmamap_t		*sc_tx_dmamaps;
		struct mbuf		**sc_rx_mbufs;
		struct mbuf		**sc_tx_mbufs;

		bus_dmamap_t		sc_ctrl_cmd_dmamap;
		bus_dmamap_t		sc_ctrl_status_dmamap;
		bus_dmamap_t		sc_ctrl_rx_dmamap;
		bus_dmamap_t		sc_ctrl_tbl_uc_dmamap;
		bus_dmamap_t		sc_ctrl_tbl_mc_dmamap;

		void			*sc_rx_softint;

		enum {
			FREE, INUSE, DONE
		}			sc_ctrl_inuse;
		kcondvar_t		sc_ctrl_wait;
		kmutex_t		sc_ctrl_wait_lock;


};

/* Declarations */

void virtio_net_identify(driver_t *driver, device_t parent);
static int virtio_net_attach(device_t dev);
static int virtio_net_detach(device_t dev);

/* ifnet interface functions */
static int	vioif_init(struct ifnet *);
static void	vioif_stop(struct ifnet *, int);
static void	vioif_start(struct ifnet *);
static int	vioif_ioctl(struct ifnet *, u_long, void *);
static void	vioif_watchdog(struct ifnet *);

/* rx */
static int	vioif_add_rx_mbuf(struct vioif_softc *, int);
static void	vioif_free_rx_mbuf(struct vioif_softc *, int);
static void	vioif_populate_rx_mbufs(struct vioif_softc *);
static int	vioif_rx_deq(struct vioif_softc *);
static int	vioif_rx_vq_done(struct virtqueue *);
static void	vioif_rx_softint(void *);
static void	vioif_rx_drain(struct vioif_softc *);

/* tx */
static int	vioif_tx_vq_done(struct virtqueue *);
static void	vioif_tx_drain(struct vioif_softc *);

/* other control */
static int	vioif_updown(struct vioif_softc *, bool);
static int	vioif_ctrl_rx(struct vioif_softc *, int, bool);
static int	vioif_set_promisc(struct vioif_softc *, bool);
static int	vioif_set_allmulti(struct vioif_softc *, bool);
static int	vioif_set_rx_filter(struct vioif_softc *);
static int	vioif_rx_filter(struct vioif_softc *);
static int	vioif_ctrl_vq_done(struct virtqueue *);
static int  vioif_destroy_vq(struct virtio_net_softc *, struct virtio_softc *, int);




/*
uint32_t
virtio_negotiate_feature(struct virtio_net_softc *sc, uint32_t guest_features)
{
	uint32_t r;

	guest_features |= VIRTIO_F_RING_INDIRECT_DESC;
	kprintf("and INDIRECT features");

	r = bus_space_read_4(sc->sc_iot, sc->sc_ioh,
				VIRTIO_CONFIG_DEVICE_FEATURES);
	kprintf("%s: r:0x%x.......x410f0020\n",__FUNCTION__,r);
	r &=guest_features;

	bus_space_write_4(sc->sc_iot, sc->sc_ioh,
			VIRTIO_CONFIG_GUEST_FEATURES, r);
	sc->sc_features = r;
	if (r & VIRTIO_F_RING_INDIRECT_DESC) {
		kprintf("%s: indirect true\n", __FUNCTION__);
		sc->sc_indirect = true;
	}
	else {
		kprintf("%s: indirect false\n",__FUNCTION__);
		sc->sc_indirect = false;
	}
	return r;
}*/

static int
vioif_init(struct ifnet *ifp){

	struct vioif_softc *sc = ifp->if_softc;

	vioif_stop(ifp, 0);
	vioif_populate_rx_mbufs(sc);
	vioif_updown
    kprintf("%s\n",__FUNCTION__);

    return 0;
}

static void
vioif_stop(struct ifnet *, int){

    kprintf("%s\n",__FUNCTION__);
    return 0;
}

static void
vioif_start(struct ifnet *){

    kprintf("%s\n",__FUNCTION__);
    return 0;
}

static int
vioif_ioctl(struct ifnet *, u_long, void *){

    kprintf("%s\n",__FUNCTION__);
    return 0;
}

static void
vioif_watchdog(struct ifnet *){

    kprintf("%s\n",__FUNCTION__);
    return 0;
}



static int
virtio_net_probe(device_t dev)
{
	
	device_t pdev = device_get_parent(dev);

	if(pci_read_config(dev,PCIR_SUBDEV_0,2) == PCI_PRODUCT_VIRTIO_NETWORK) {
		debug("parent:%p is net\n", pdev);
	} else {
		debug("parent:%p is not net\n");
		return 1;
	}

	return 0;

}


static int
virtio_net_attach(device_t dev)
{

	struct virtio_net_softc *sc = device_get_softc(dev);
	device_t pdev = device_get_parent(dev);
	struct virtio_softc *vsc = device_get_softc(pdev);
	uint32_t features;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	int error;
	struct resource *io;

	debug("");

//	int  qsize;

	sc->dev = dev;
	sc->sc_virtio = vsc;

	vsc->sc_vqs = &sc->sc_vq[RX_VQ];
	vsc->sc_config_change = 0;
	vsc->sc_child = dev;
	vsc->sc_ipl = IPL_NET;

	vsc->sc_config_change = 0; /* keep it?*/
	vsc->sc_intrhand = virtio_vq_intr;

	debug("sc_child is %p\n", vsc->sc_child);

	features = virtio_negotiate_feature(vsc,
						(VIRTIO_NET_F_MAC |
						 VIRTIO_NET_F_STATUS |
						 VIRTIO_NET_F_CTRL_VQ |
						 VIRTIO_NET_F_CTRL_RX |
						 VIRTIO_F_NOTIFY_ON_EMPTY));
		if (features & VIRTIO_NET_F_MAC) {
			sc->sc_mac[0] = virtio_read_device_config(vsc,
							    VIRTIO_NET_CONFIG_MAC+0);
			sc->sc_mac[1] = virtio_read_device_config(vsc,
							    VIRTIO_NET_CONFIG_MAC+1);
			sc->sc_mac[2] = virtio_read_device_config(vsc,
							    VIRTIO_NET_CONFIG_MAC+2);
			sc->sc_mac[3] = virtio_read_device_config(vsc,
							    VIRTIO_NET_CONFIG_MAC+3);
			sc->sc_mac[4] = virtio_read_device_config(vsc,
							    VIRTIO_NET_CONFIG_MAC+4);
			sc->sc_mac[5] = virtio_read_device_config(vsc,
							    VIRTIO_NET_CONFIG_MAC+5);
		} else {
			/* code stolen from sys/net/if_tap.c */
			struct timeval tv;
			uint32_t ui;
			getmicrouptime(&tv);
			ui = (tv.tv_sec ^ tv.tv_usec) & 0xffffff;
			memcpy(vsc->sc_mac+3, (uint8_t *)&ui, 3);
			virtio_write_device_config(vsc,
						     VIRTIO_NET_CONFIG_MAC+0,
						     vsc->sc_mac[0]);
			virtio_write_device_config(vsc,
						     VIRTIO_NET_CONFIG_MAC+1,
						     vsc->sc_mac[1]);
			virtio_write_device_config(vsc,
						     VIRTIO_NET_CONFIG_MAC+2,
						     vsc->sc_mac[2]);
			virtio_write_device_config(vsc,
						     VIRTIO_NET_CONFIG_MAC+3,
						     vsc->sc_mac[3]);
			virtio_write_device_config(vsc,
						     VIRTIO_NET_CONFIG_MAC+4,
						     vsc->sc_mac[4]);
			virtio_write_device_config(vsc,
						     VIRTIO_NET_CONFIG_MAC+5,
						     vsc->sc_mac[5]);
		}

	kprintf(":Ethernet address %s\n", ether_sprintf(sc->sc_mac));

	kprintf("Attach started ->> %s\n",__FUNCTION__);

	/* Virtqueue allocation for the rx queue. */
	error = virtio_alloc_vq(sc,&sc->sc_vq[RX_VQ],0,
				MCLBYTES+sizeof(struct virtio_net_hdr),2,
				"rx vq");
	if (error != 0)	{
		kprintf("Virtqueue allocation for rx failed\n");
		goto err;
	}
	vsc->sc_nvqs = 1;
	sc->sc_vq[RX_VQ].vq_done = vioif_rx_vq_done; /* rx interrupt*/

	/* Virtqueue allocation for the tx queue. */
	error = virtio_alloc_vq(vsc, &sc->sc_vq[TX_VQ], 1,
		    	(sizeof(struct virtio_net_hdr)
		    	+ (ETHER_MAX_LEN - ETHER_HDR_LEN)),
		    	VIRTIO_NET_TX_MAXNSEGS + 1,
		    	"tx vq");
	if (error != 0){
		kprintf("Virtqueue allocation for tx failed\n");
		goto err;
	}
	vsc->sc_nvqs = 2;
	sc->sc_vq[TX_VQ].vq_done = vioif_tx_vq_done; /* tx interrupt*/

	virtio_start_vq_intr(vsc, &sc->sc_vq[RX_VQ]);
	virtio_stop_vq_intr(vscc, &sc->sc_vq[TX_VQ]);


	/* Virtqueue allocation for the ctrl queue */
	if ((features & VIRTIO_NET_F_CTRL_VQ)
		&& (features & VIRTIO_NET_F_CTRL_RX)){ /* rx & ctrl queues */
		error = virtio_alloc_vq(vsc, &sc->sc_vq[CTRL_VQ], 2,
			    NBPG, 1, "control vq");

		if (error != 0){
			kprintf("Virtqueue allocation for control failed\n");
			goto err;
		}

		vsc->sc_nvqs = 3;
		sc->sc_vq[CTRL_VQ].vq_done = vioif_ctrl_vq_done;

		cv_init(&sc->sc_ctrl_wait, "ctrl_vq");
		mutex_init(&sc->sc_ctrl_wait_lock, MUTEX_DEFAULT, IPL_NET);
		sc->sc_ctrl_inuse = FREE;

		virtio_start_vq_intr(vsc, &sc->sc_vq[CTRL_VQ]);
	}

	sc->sc_rx_softint = softint_establish(SOFTINT_NET|SOFTINT_MPSAFE,
						      vioif_rx_softint, sc);
	if (sc->sc_rx_softint == NULL) {
		aprint_error_dev(self, "cannot establish softint\n");
		goto err;
	}

	/* Memory allocation for the control queue (for virtio_softc) */
	if (vioif_alloc_mems(sc) < 0)
		goto err;

	if (vsc->sc_nvqs == 3)
		config_interrupts(self, vioif_deferred_init);

	/* Interface for the device switch */
	strlcpy(ifp->if_xname, device_xname(dev), IFNAMSIZ);
	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_start = vioif_start;
	ifp->if_ioctl = vioif_ioctl;
	ifp->if_init = vioif_init;
	ifp->if_stop = vioif_stop;
	ifp->if_capabilities = 0;
	ifp->if_watchdog = vioif_watchdog;

	if_attach(ifp);
	ether_ifattach(ifp, sc->sc_mac);

	kprintf("%s","CONFIG_DEVICE_STATUS_DRIVER");
	virtio_set_status(vsc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);

    return 0;

err:
	kprintf("%s failure\n", __FUNCTION__);
	if (vsc->sc_nvqs == 3) {
		virtio_free_vq(vsc, &sc->sc_vq[CTRL_VQ]);
		cv_destroy(&sc->sc_ctrl_wait);
		mutex_destroy(&sc->sc_ctrl_wait_lock);
		vsc->sc_nvqs = 2;
	}
	if (vsc->sc_nvqs == 2) {
		virtio_free_vq(vsc, &sc->sc_vq[TX_VQ]);
		vsc->sc_nvqs = 1;
	}
	if (vsc->sc_nvqs == 1) {
		virtio_free_vq(vsc, &sc->sc_vq[RX_VQ]);
		vsc->sc_nvqs = 0;
	}
	vsc->sc_child = (void*)1;
	return 1;
}

static int
virtio_net_detach(device_t dev)
{
	kprintf("%s\n",__FUNCTION__);
	struct virtio_net_softc *sc = device_get_softc(dev);
	device_t pdev = device_get_parent(sc->dev);
	struct virtio_softc *vsc = device_get_softc(pdev);

	vioif_destroy_vq(sc, vsc, RX_VQ); /* destroy rx vq */
	vioif_destroy_vq(sc, vsc, TX_VQ); /* destroy tx vq */
	vioif_destroy_vq(sc, vsc, CTRL_VQ); /* destroy ctrl vq */

	/* anything else ? */

	return 0;
}

/* Unload and free &sc->sc_vq[number] */
static int
vioif_destroy_vq(virtio_net_softc *sc, virtio_softc *vsc, int numq ){

	struct virtqueue *vq = &sc->sc_vq[numq];
	int i;


	/*for (i=0; i<sc->sc_vq[number].vq_num; i++){
		struct virtio_blk_req *vr = &sc->sc_reqs[i];

		bus_dmamap_destroy(vsc->payloads_dmat, vr->payload_dmap);

		bus_dmamap_unload(vsc->requests_dmat, vr->cmd_dmap);
		bus_dmamap_destroy(vsc->requests_dmat, vr->cmd_dmap);
	}*/


	virtio_reset(vsc);
	virtio_free_vq(vsc, &sc->sc_vq[numq]);

	/*unload and free virtqueue*/
	kfree(vq->vq_entries, M_DEVBUF);
	bus_dmamap_unload(vq->vq_dmat, vq->vq_dmamap);
	bus_dammem_free(vq->vq_dmat, vq->vq_addr, vq->vq_dmamap);
	bus_dam_tag_destroy(vq->vq_dmat);
	memset(vq, 0, sizeof(*vq));

	/* free net-related stuff */

	return 0;
}

static device_method_t virtio_net_methods[] = {
	DEVMETHOD(device_probe,         virtio_net_probe),
	DEVMETHOD(device_attach,        virtio_net_attach),
	DEVMETHOD(device_detach,        virtio_net_detach),
	{ 0, 0 }
};

static driver_t virtio_net_driver = {
	"virtio_net",
	virtio_net_methods,
	sizeof(struct virtio_net_softc),
};

static devclass_t virtio_net_devclass;

DRIVER_MODULE(virtio_net, virtiobus, virtio_net_driver, virtio_net_devclass, 0, 0);
MODULE_DEPEND(virtio_net, virtiobus, 0, 0, 0);
