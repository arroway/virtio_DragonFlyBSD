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
#include <sys/bus_dma.h>
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
#include <net/if_arp.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/if_media.h>

#include <sys/spinlock.h>
#include <sys/spinlock2.h>
#include <sys/kthread.h>
#include <sys/serialize.h>
#include <sys/msgport.h>
#include <sys/msgport2.h>
#include <sys/mplock2.h>
#include <vm/vm_extern.h>
#if 0
#include <cpu/i386/include/cpufunc.h>
#include <cpu/i386/include/atomic.h>
#endif

#include <dev/netif/mii_layer/miivar.h>
#include <dev/virtio/virtiovar.h>
#include <dev/virtio/virtioreg.h>
#include <dev/virtio/net/virtio-net.h>

#define NDEVNAMES	(sizeof(virtio_device_name)/sizeof(char*))
#define MINSEG_INDIRECT     2 /* use indirect if nsegs >= this value */


/* Declarations */

void vioif_identify(driver_t *driver, device_t parent);
static int vioif_attach(device_t dev);
static int vioif_detach(device_t dev);
static int vioif_destroy_vq(struct vioif_softc *, struct virtio_softc *, int, bool);


/* ifnet interface functions */
static void vioif_init(void *);
static void	vioif_down(struct ifnet *, int);
static void	vioif_start(struct ifnet *);
static int	vioif_ioctl(struct ifnet *, u_long, caddr_t, struct ucred *);
static void	vioif_watchdog(struct ifnet *);

/* rx */
static int	vioif_add_rx_mbuf(struct vioif_softc *, int);
static void	vioif_free_rx_mbuf(struct vioif_softc *, int);
static void	vioif_populate_rx_mbufs(struct vioif_softc *);
static int	vioif_rx_deq(struct vioif_softc *);
static int	vioif_rx_vq_done(struct virtqueue *);
static void vioif_rx_task(void *, int);
static void	vioif_rx_drain(struct vioif_softc *);

/* tx */
static int	vioif_tx_vq_done(struct virtqueue *);
static void	vioif_tx_drain(struct vioif_softc *);

/* other control */
static int	vioif_updown(struct vioif_softc *, struct ifnet *, bool);
static int	vioif_ctrl_rx(struct vioif_softc *, int, bool);
static int	vioif_set_promisc(struct vioif_softc *, bool);
static int	vioif_set_allmulti(struct vioif_softc *, bool);
static int	vioif_set_rx_filter(struct vioif_softc *);
static int	vioif_rx_filter(struct vioif_softc *);
static int	vioif_ctrl_vq_done(struct virtqueue *);
static void vioif_deferred_init(device_t );
static void vioif_set_promisc_init(void *);

/* memory allocation and callback functions */
static int vioif_alloc_mems(struct vioif_softc *);
static void dmamap_create(struct vioif_softc *, bus_dmamap_t, int, char*);
static void dmamap_destroy(bus_dma_tag_t, bus_dmamap_t);
static void dmamap_error(struct vioif_softc *, int, int, char*);
static void rxhdr_load_callback(void *, bus_dma_segment_t *, int, int);
static void txhdr_load_callback(void *, bus_dma_segment_t *, int, int);
static void cmd_load_callback(void *, bus_dma_segment_t *, int, int);
static void rx_load_mbuf_callback(void *, bus_dma_segment_t *, int, bus_size_t, int);
static void tx_load_mbuf_callback(void *, bus_dma_segment_t *, int, bus_size_t, int);
static int ifm_change_callback(struct ifnet *);
static void ifm_status_callback(struct ifnet *, struct ifmediareq *);

/* Callback function for rx header */
static void
rxhdr_load_callback(void *callback_arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct vioif_softc *sc = (struct vioif_softc *) callback_arg;
	int i;

	if (error != 0){
		debug("error %u in rxhdr_load_callback\n", error);
		return;
	}

	/* Temporarily save information there */
	sc->sc_nseg_temp_rx = nseg; /* How much segments there is */

	for(i=0; i<nseg ; i++){
		sc->sc_segment_temp_rx[i] = segs[i]; /* Save segments information */
		//debug("seg %d len:%08X, sc->sc_segment_temp_rx[i].ds_len: %08X ", i, segs[i].ds_len, sc->sc_segment_temp_rx[i].ds_len);
	
	}

    return;
}

/* Callback function for tx header */
static void
txhdr_load_callback(void *callback_arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct vioif_softc *sc = (struct vioif_softc *) callback_arg;
	int i;

	if (error != 0){
		debug("error %u in txhdr_load_callback\n", error);
		return;
	}


	/* Temporarily save information there */
	sc->sc_nseg_temp_tx = nseg; /* How much segments there is */

	for(i = 0; i<nseg ; i++){
		sc->sc_segment_temp_tx[i] = segs[i]; /* Save segments information */
		//debug("seg %d len:%08X, sc->sc_segment_temp_tx[i].ds_len: %08X ", i, segs[i].ds_len, sc->sc_segment_temp_tx[i].ds_len);

	}

    return;
}

/* Callback function for command virtqueue functions */
static void
cmd_load_callback(void *callback_arg, bus_dma_segment_t *segs, int nseg, int error)
{
	struct vioif_softc *sc = (struct vioif_softc *) callback_arg;
	int i;

	if (error != 0){
		debug("error %u on cmd_load_callback\n", error);
		return;
	}


	/* Temporarily save information there */
	sc->sc_ctrl_nseg_temp = nseg; /* How many segments there is */
	debug("nseg = %d", nseg);

	for(i = 0; i< nseg ; i++){
		sc->sc_ctrl_segment_temp[i] = segs[i]; /* Save segments information */
		//debug("seg %d len:%08X, sc->sc_ctrl_segment_temp[i].ds_len: %08X ", i, segs[i].ds_len, sc->sc_ctrl_segment_temp[i].ds_len);

	}

    return;
}


/* Callback function for rx packets*/
static void
rx_load_mbuf_callback(void *callback_arg, bus_dma_segment_t *segs, int nseg, bus_size_t size, int error)
{
	struct vioif_softc *sc = (struct vioif_softc *) callback_arg;
	int i;

	if (error != 0){
		debug("error %u on rx_load_mbuf_callback\n", error);
		return;
	}

	/* Temporarily save information there */
	sc->sc_nseg_temp_rx = nseg; /* How much segments there is */
	debug("nseg = %d", nseg);


	for(i = 0; i<nseg ; i++){
		sc->sc_segment_temp_rx[i] = segs[i]; /* Save segments information */
	  	//debug("seg %d len:%08X, sc->sc_segment_temp_rx[i].ds_len: %08X ", i, segs[i].ds_len, sc->sc_segment_temp_rx[i].ds_len);

	}

    return;
}

/* Callback function for tx packets*/
static void
tx_load_mbuf_callback(void *callback_arg, bus_dma_segment_t *segs, int nseg, bus_size_t size, int error)
{
	struct vioif_softc *sc = (struct vioif_softc *) callback_arg;
	int i;

	if (error != 0){
		debug("error %u on tx_load_mbuf_callback\n", error);
		return;
	}


	/* Temporarily save information there */
	sc->sc_nseg_temp_tx = nseg; /* How much segments there is */
	debug("nseg = %d", nseg);

	for(i = 0; i<nseg ; i++){
		sc->sc_segment_temp_tx[i] = segs[i]; /* Save segments information */
		//debug("seg %d len:%08X, sc->sc_segment_temp_tx[i].ds_len: %08X ", i, segs[i].ds_len, sc->sc_segment_temp_tx[i].ds_len);
	}

    return;
}


static void
vioif_init(void *arg)
{
	struct ifnet *ifp = arg;
	struct vioif_softc *sc = ifp->if_softc;
	struct virtio_softc *vsc = sc->sc_virtio;

	vioif_down(ifp, 0);
	virtio_reinit_end(vsc);
	///vioif_populate_rx_mbufs(sc);
	vioif_updown(sc, ifp, true);

	ifp->if_flags |= IFF_RUNNING;
	ifp->if_flags &= ~IFF_OACTIVE;
	
	vioif_populate_rx_mbufs(sc);
	vioif_rx_filter(sc);

}

static void
vioif_down(struct ifnet *ifp, int disable)
{
	struct vioif_softc *sc = ifp->if_softc;
	struct virtio_softc *vsc = sc->sc_virtio;

	virtio_reset(vsc);
	vioif_rx_deq(sc);
	vioif_tx_drain(sc);

	ifp->if_flags &= ~(IFF_RUNNING | IFF_OACTIVE);

	if (disable)
		vioif_rx_drain(sc);


	virtio_reinit_start(vsc);
	virtio_negotiate_features(vsc, sc->sc_features);
	virtio_start_vq_intr(vsc, &sc->sc_vq[RX_VQ]);
	virtio_stop_vq_intr(vsc, &sc->sc_vq[TX_VQ]);

	if (vsc->sc_nvqs >= 3)
		virtio_start_vq_intr(vsc, &sc->sc_vq[CTRL_VQ]);

	/* Reseting twice is NOT nice */
	//virtio_reset(vsc);
	vioif_updown(sc, ifp, false);
}


/* 	ifp->if_start  */
static void
vioif_start(struct ifnet *ifp)
{
	struct vioif_softc *sc = ifp->if_softc;
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = &sc->sc_vq[TX_VQ]; /* tx vq */
	struct mbuf *m;
	int queued;
	int retry = 0;
	int slot, r, i;


	ASSERT_SERIALIZED(ifp->if_serializer);

	if ((ifp->if_flags & (IFF_RUNNING|IFF_OACTIVE)) != IFF_RUNNING)
		return;
	
	queued = 0;

	while ((m = ifq_poll(&ifp->if_snd)) != NULL) {

		r = virtio_enqueue_prep(vsc, vq, &slot);

		if (r == EAGAIN){
			ifp->if_flags |= IFF_OACTIVE;
			/*tx interrupt*/
			vioif_tx_vq_done(vq);

			if (retry++ == 0)
				continue;
			else
				break;
		}

		if (r != 0){
			debug("no slot available\n ");
			break;
		}

		/* Maps mbuf chains*/
	    	r = bus_dmamap_load_mbuf(sc->sc_txbuf_dmat,
	    		sc->sc_tx_dmamaps[slot],
	    		m,
	    		tx_load_mbuf_callback,
	    		sc,
	    		0);

	        if (r != 0) {
			virtio_enqueue_abort(vsc, vq, slot);
			m_freem(m);
			debug("tx dmamap load failed\n");
			return;
		}

		sc->sc_tx_nseg[slot] = sc->sc_nseg_temp_tx;
		//debug("sc->sc_tx_nseg[slot]: %d", sc->sc_tx_nseg[slot]);
		sc->sc_tx_segment[slot] = sc->sc_segment_temp_tx;
		for (i=0; i<sc->sc_tx_nseg[slot]; i++){
			debug("sc->sc_tx_segment[%d][%d].ds_len: %lu", slot, i, sc->sc_tx_segment[slot][i].ds_len);
		}
		
		sc->sc_vq[TX_VQ].vq_desc[slot].addr = 	sc->sc_tx_segment[slot]->ds_addr; /* Save physical address */
		debug("tx mbuf: sc->sc_vq[TX_VQ].vq_desc[%d].addr: %08X", slot, sc->sc_vq[TX_VQ].vq_desc[slot].addr);
		

		r = virtio_enqueue_reserve(vsc, vq, slot, sc->sc_tx_nseg[slot] + sc->sc_txhdr_nseg[slot]);

		if (r != 0) {

			bus_dmamap_sync(sc->sc_txbuf_dmat, sc->sc_tx_dmamaps[slot], BUS_DMASYNC_PREWRITE);
			bus_dmamap_unload(sc->sc_txbuf_dmat, sc->sc_tx_dmamaps[slot]);
			ifp->if_flags |= IFF_OACTIVE;
			vioif_tx_vq_done(vq);

			if (retry++ == 0)
				continue;
			else
				break;
		}

		m = ifq_dequeue(&ifp->if_snd, 0);
		if (m == NULL){
			debug("mbuf after dequeue is null");
			break;
		}

		sc->sc_tx_mbufs[slot] = m;
		memset(&sc->sc_tx_hdrs[slot], 0, sizeof(struct virtio_net_hdr));

		bus_dmamap_sync(sc->sc_txbuf_dmat, sc->sc_tx_dmamaps[slot], BUS_DMASYNC_PREWRITE);
		bus_dmamap_sync(sc->sc_txbuf_dmat, sc->sc_txhdr_dmamaps[slot], BUS_DMASYNC_PREWRITE);

		virtio_enqueue(vsc, vq, slot, sc->sc_txhdr_segment[slot],sc->sc_txhdr_nseg[slot], sc->sc_txhdr_dmamaps[slot], true);
		virtio_enqueue(vsc, vq, slot, sc->sc_tx_segment[slot],sc->sc_tx_nseg[slot], sc->sc_tx_dmamaps[slot], true);

		/* add to the transmit ring */
		virtio_enqueue_commit(vsc, vq, slot, false);

		queued = 1;

#if NBPFILTER > 0
		if (ifp->if_bpf)
			/* if there is a NBPFILTER, bounce a copy of this frame to him */
			bpf_mtap(ifp->if_bpf, m);
#endif

	}

	if (queued > 0) {
		/* transmitting */
		virtio_enqueue_commit(vsc, vq, -1, true);
		/* set a timer */
		ifp->if_timer = 5;
	}
}


static int ifm_change_callback(struct ifnet* ifp)
{
	ASSERT_SERIALIZED(ifp->if_serializer);
	return 0;	
}

static void ifm_status_callback(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	ASSERT_SERIALIZED(ifp->if_serializer);
	ifmr->ifm_active = IFM_ETHER|IFM_1000_T;
}

/* 	ifp->if_ioctl  */
static int
vioif_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data, struct ucred *cr)
{
	struct vioif_softc *sc = ifp->if_softc;
	struct ifreq *ifr;
	int r = 0;

	ASSERT_SERIALIZED(ifp->if_serializer);

	ifr = (struct ifreq *) data;

	switch (cmd) {
	case SIOCGIFMEDIA:
	case SIOCSIFMEDIA:
		r = ifmedia_ioctl(ifp, ifr, &sc->sc_ifm, cmd);
		break;

	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP) {
			if (ifp->if_flags & IFF_RUNNING) {
				if (((ifp->if_flags ^ sc->sc_if_flags)
				    & (IFF_PROMISC | IFF_ALLMULTI)) != 0)
					r = vioif_rx_filter(sc);
			} else {
				vioif_init(ifp);
			}
		} else {
			if (ifp->if_flags & IFF_RUNNING)
				vioif_down(ifp, /* disable */1);
		}
		sc->sc_if_flags = ifp->if_flags;
		break;

	default:
		r = ether_ioctl(ifp, cmd, data);
	}

	return r;
}

/* ifp->if_watchdog */
static void
vioif_watchdog(struct ifnet *ifp)
{
	struct vioif_softc *sc = ifp->if_softc;

	if (ifp->if_flags & IFF_RUNNING)
		vioif_tx_vq_done(&sc->sc_vq[TX_VQ]);
}


/* change link status */
static int
vioif_updown(struct vioif_softc *sc, struct ifnet *ifp, bool isup)
{
	struct virtio_softc *vsc = sc->sc_virtio;

	if (!(vsc->sc_features & VIRTIO_NET_F_STATUS))
		return ENODEV;

	bus_space_write_1(vsc->sc_iot, vsc->sc_ioh,
				     VIRTIO_NET_CONFIG_STATUS,
				     isup?VIRTIO_NET_S_LINK_UP:0);

	if (ifp != NULL) {
		ifp->if_link_state = (isup) ? LINK_STATE_UP : LINK_STATE_DOWN;
		if_link_state_change(ifp);
	}
	return 0;
}

/* Allocate memory
 *
 * dma memory is used for:
 *   sc_rx_hdrs[slot]:	 metadata array for recieved frames (READ)
 *   sc_tx_hdrs[slot]:	 metadata array for frames to be sent (WRITE)
 *   sc_ctrl_cmd:	 command to be sent via ctrl vq (WRITE)
 *   sc_ctrl_status:	 return value for a command via ctrl vq (READ)
 *   sc_ctrl_rx:	 parameter for a VIRTIO_NET_CTRL_RX class command
 *			 (WRITE)
 *   sc_ctrl_mac_tbl_uc: unicast MAC address filter for a VIRTIO_NET_CTRL_MAC
 *			 class command (WRITE)
 *   sc_ctrl_mac_tbl_mc: multicast MAC address filter for a VIRTIO_NET_CTRL_MAC
 *			 class command (WRITE)
 * sc_ctrl_* structures are allocated only one each; they are protected by
 * sc_ctrl_inuse variable and sc_ctrl_wait condvar.
 *
 *
 * dynamically allocated memory is used for:
 *   sc_rxhdr_dmamaps[slot]:	bus_dmamap_t array for sc_rx_hdrs[slot]
 *   sc_txhdr_dmamaps[slot]:	bus_dmamap_t array for sc_tx_hdrs[slot]
 *   sc_rx_dmamaps[slot]:	bus_dmamap_t array for recieved payload
 *   sc_tx_dmamaps[slot]:	bus_dmamap_t array for sent payload
 *   sc_rx_mbufs[slot]:		mbuf pointer array for recieved frames
 *   sc_tx_mbufs[slot]:		mbuf pointer array for sent frames
 *
 *
 */

/* Auxiliary functions used in vioif_alloc_mems() */

static void
dmamap_create(struct vioif_softc *sc, bus_dmamap_t map, int allocsize2, char *usage)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	int r;

	do {
		r = bus_dmamap_create(vsc->requests_dmat, BUS_DMA_NOWAIT|BUS_DMA_ALLOCNOW, &map);
		if (r !=0 ){
			dmamap_error(sc, r, allocsize2, usage);
		}

	} while (0);

}


static void
dmamap_destroy(bus_dma_tag_t dma_tag, bus_dmamap_t map)
{
	do {
		if (map) {
			bus_dmamap_destroy(dma_tag, map);
			map = NULL;
		}

	} while (0);
}


static void
dmamap_error(struct vioif_softc *sc, int r, int allocsize2, char *usage)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	int rxqsize = vsc->sc_vqs[RX_VQ].vq_num;
	int txqsize = vsc->sc_vqs[TX_VQ].vq_num;
	int i;

	debug("fail: %s" "error code %d\n", usage, r);

	dmamap_destroy(vsc->requests_dmat, sc->sc_ctrl_tbl_mc_dmamap);
	dmamap_destroy(vsc->requests_dmat, sc->sc_ctrl_tbl_uc_dmamap);
	dmamap_destroy(vsc->requests_dmat, sc->sc_ctrl_rx_dmamap);
	dmamap_destroy(vsc->requests_dmat, sc->sc_ctrl_status_dmamap);
	dmamap_destroy(vsc->requests_dmat, sc->sc_ctrl_cmd_dmamap);

	for (i = 0; i < txqsize; i++) {

		dmamap_destroy(vsc->requests_dmat, sc->sc_tx_dmamaps[i]);
		dmamap_destroy(vsc->requests_dmat, sc->sc_txhdr_dmamaps[i]);
	}
	for (i = 0; i < rxqsize; i++) {

		dmamap_destroy(vsc->requests_dmat, sc->sc_rx_dmamaps[i]);
		dmamap_destroy(vsc->requests_dmat, sc->sc_arrays[i]);
	}

	if (sc->sc_rxhdr_dmamaps) {
		bus_dmamem_free(vsc->requests_dmat,
				&sc->sc_vq[RX_VQ].vq_desc->addr,
				*sc->sc_rxhdr_dmamaps);
		sc->sc_rxhdr_dmamaps = 0;
	}
}

static int
vioif_alloc_mems(struct vioif_softc *sc)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	int allocsize, allocsize2, r, i;
	void *vaddr;
	intptr_t p;
	int rxqsize, txqsize;

	rxqsize = vsc->sc_vqs[RX_VQ].vq_num;
	txqsize = vsc->sc_vqs[TX_VQ].vq_num;

	/* Dynamically allocate memory to save information about nseg */
	MALLOC(sc->sc_rxhdr_nseg,int *,
			(rxqsize * sizeof(int)), M_DEVBUF, M_ZERO);
	MALLOC(sc->sc_txhdr_nseg, int *,
			(txqsize * sizeof(int)), M_DEVBUF, M_ZERO);

	/* allocation for later use in vioif_populate_rx_mbufs */
	MALLOC(sc->sc_rx_nseg, int *,
			(rxqsize * sizeof(int)), M_DEVBUF, M_ZERO);
	MALLOC(sc->sc_tx_nseg, int *,
			(txqsize * sizeof(int)), M_DEVBUF, M_ZERO);

	/* Dynamically allocate memory to save information about segments
	 *  of bus_dmamap_t structures */
	MALLOC(sc->sc_rxhdr_segment,
			bus_dma_segment_t **,
			txqsize * sizeof(bus_dma_segment_t *), M_DEVBUF, M_ZERO);
	MALLOC(sc->sc_txhdr_segment,
			bus_dma_segment_t **,
			(txqsize * sizeof(bus_dma_segment_t *)), M_DEVBUF, M_ZERO);

	/* allocation for later use in vioif_populate_rx_mbufs */
	MALLOC(sc->sc_rx_segment,
			bus_dma_segment_t **,
			(rxqsize * sizeof(bus_dma_segment_t *)), M_DEVBUF, M_ZERO);
	MALLOC(sc->sc_tx_segment,
			bus_dma_segment_t **,
			(txqsize * sizeof(bus_dma_segment_t *)), M_DEVBUF, M_ZERO);

	MALLOC(sc->sc_ctrl_cmd_segment,
			bus_dma_segment_t *,
			(1 * sizeof(bus_dma_segment_t)), M_DEVBUF, M_ZERO);
	MALLOC(sc->sc_ctrl_status_segment,
			bus_dma_segment_t *,
			(1 * sizeof(bus_dma_segment_t)), M_DEVBUF, M_ZERO);
	MALLOC(sc->sc_ctrl_rx_segment,
			bus_dma_segment_t *,
			(1 * sizeof(bus_dma_segment_t)), M_DEVBUF, M_ZERO);

	MALLOC(sc->sc_ctrl_uc_segment,
			bus_dma_segment_t *,
			(1 * sizeof(bus_dma_segment_t)), M_DEVBUF, M_ZERO);
	MALLOC(sc->sc_ctrl_mc_segment,
			bus_dma_segment_t *,
			(1 * sizeof(bus_dma_segment_t)), M_DEVBUF, M_ZERO);


	/* temp
	 * bug in size, don't know the right size */
	MALLOC(sc->sc_segment_temp_rx,
			bus_dma_segment_t *,
			(rxqsize * sizeof(bus_dma_segment_t)), M_DEVBUF, M_ZERO);
	MALLOC(sc->sc_segment_temp_tx,
			bus_dma_segment_t *,
			(txqsize * sizeof(bus_dma_segment_t)), M_DEVBUF, M_ZERO);
	MALLOC(sc->sc_ctrl_segment_temp,
			bus_dma_segment_t *,
			(2 * sizeof(bus_dma_segment_t)), M_DEVBUF, M_ZERO);

	allocsize = sizeof(struct virtio_net_hdr) * rxqsize;
	allocsize += sizeof(struct virtio_net_hdr) * txqsize;

	if (vsc->sc_nvqs == 3) {
		allocsize += sizeof(struct virtio_net_ctrl_cmd) * 1;
		allocsize += sizeof(struct virtio_net_ctrl_status) * 1;
		allocsize += sizeof(struct virtio_net_ctrl_rx) * 1;
		allocsize += sizeof(struct virtio_net_ctrl_mac_tbl)
			+ sizeof(struct virtio_net_ctrl_mac_tbl)
			+ ETHER_ADDR_LEN * VIRTIO_NET_CTRL_MAC_MAXENTRIES;
	}

	r = bus_dma_tag_create(vsc->virtio_dmat,
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

	if (r != 0) {
		kprintf("requests_dmat tag create failed\n");
		return(1);
	}


	r = bus_dma_tag_create(0, 1,
			0,
			BUS_SPACE_MAXADDR,
			BUS_SPACE_MAXADDR,
			NULL, NULL,
			allocsize,
			0,
			BUS_SPACE_MAXSIZE_32BIT,
			0, &sc->sc_hdr_dmat);


	if (r != 0) {
		debug("DMA tag memory allocation failed, size %d, ""error code %d\n", allocsize, r);
		goto err_none;
	}
	
   	r = bus_dma_tag_create(NULL, 
		1, 
		0,
		BUS_SPACE_MAXADDR,
		BUS_SPACE_MAXADDR,
		NULL, NULL,
		32 * MCLBYTES,
		32,
		MCLBYTES,
		0,
		&sc->sc_txbuf_dmat);

	if (r != 0){
		debug("Tx DMA tag memory for allocation failed, size %d, ""error code %d\n", MCLBYTES, r);
		goto err_none;
	}

	r = bus_dmamem_alloc(sc->sc_hdr_dmat,
			&vaddr,
			BUS_DMA_NOWAIT,
			&sc->sc_hdr_dmamap);

	if (r != 0) {
		debug("DMA memory allocation failed, size %d, ""error code %d\n", allocsize, r);
		goto err_none;
	}

	sc->sc_hdrs = vaddr;
	memset(vaddr, 0, allocsize);
	p = (intptr_t) vaddr;
	p += sizeof(struct virtio_net_hdr) * rxqsize;

#define P(name,size)	do { sc->sc_ ##name = (void*) p;	\
			     p += size; } while (0)

	P(tx_hdrs, sizeof(struct virtio_net_hdr) * txqsize);

	if (vsc->sc_nvqs == 3) {
		P(ctrl_cmd, sizeof(struct virtio_net_ctrl_cmd));
		P(ctrl_status, sizeof(struct virtio_net_ctrl_status));
		P(ctrl_rx, sizeof(struct virtio_net_ctrl_rx));
		P(ctrl_mac_tbl_uc, sizeof(struct virtio_net_ctrl_mac_tbl));
		P(ctrl_mac_tbl_mc,
		  (sizeof(struct virtio_net_ctrl_mac_tbl)
		   + ETHER_ADDR_LEN * VIRTIO_NET_CTRL_MAC_MAXENTRIES));
	}

#undef P

	allocsize2 = sizeof(bus_dmamap_t) * (rxqsize + txqsize);
	allocsize2 += sizeof(bus_dmamap_t) * (rxqsize + txqsize);
	allocsize2 += sizeof(struct mbuf*) * (rxqsize + txqsize);
	sc->sc_rxhdr_dmamaps = kmalloc(allocsize2, M_DEVBUF, M_ZERO|M_WAITOK);

	if (&sc->sc_rxhdr_dmamaps == NULL) {
		debug("reception header for rx dmamap is NULL.\n");
		goto err_dmamem_map;
	}

	sc->sc_txhdr_dmamaps = sc->sc_arrays + rxqsize;
	sc->sc_rx_dmamaps = sc->sc_txhdr_dmamaps + txqsize;
	sc->sc_tx_dmamaps = sc->sc_rx_dmamaps + rxqsize;
	sc->sc_rx_mbufs = (void*) (sc->sc_tx_dmamaps + txqsize);
	sc->sc_tx_mbufs = sc->sc_rx_mbufs + rxqsize;

	/* Rx allocation - for each slot */
	for (i = 0; i < rxqsize; i++){

		/* rx header */
		r = bus_dmamap_load(vsc->requests_dmat,
				sc->sc_arrays[i],
				&sc->sc_rx_hdrs[i],
				sizeof(struct virtio_net_hdr),
				rxhdr_load_callback,
				sc,
				0);

		if (r != 0)
			dmamap_error(sc, r, allocsize2, "rx header");

		sc->sc_rxhdr_nseg[i] = sc->sc_nseg_temp_rx;
		sc->sc_rxhdr_segment[i] = sc->sc_segment_temp_rx;

		sc->sc_vq[RX_VQ].vq_desc[i].addr = sc->sc_rxhdr_segment[i]->ds_addr; /* Save physical address */
		debug("sc_vq[RX_VQ].vq_desc[%d].addr = %08X ", i, sc->sc_vq[RX_VQ].vq_desc[i].addr);
				

		dmamap_create(sc,
				sc->sc_rx_dmamaps[i],
				allocsize2,
				"rx_payload");
	}

	/* Tx allocation - for each slot */
	for (i = 0; i < txqsize; i++){

		/* tx header */
		r = bus_dmamap_load(vsc->requests_dmat,
				sc->sc_txhdr_dmamaps[i],
				&sc->sc_tx_hdrs[i],
				sizeof(struct virtio_net_hdr),
				txhdr_load_callback,
				sc,
				0);

		if (r != 0)
			dmamap_error(sc, r, allocsize2, "tx header");

		sc->sc_txhdr_nseg[i] = sc->sc_nseg_temp_tx;
		sc->sc_txhdr_segment[i] = sc->sc_segment_temp_tx;

		sc->sc_vq[TX_VQ].vq_desc[i].addr = sc->sc_txhdr_segment[i]->ds_addr; /* Save physical address */
		debug("sc_vq[TX_VQ].vq_desc[%d].addr = %08X ", i, sc->sc_vq[TX_VQ].vq_desc[i].addr);


		r = bus_dmamap_create(sc->sc_txbuf_dmat, BUS_DMA_NOWAIT|BUS_DMA_ALLOCNOW, &sc->sc_tx_dmamaps[i]);
		
		if (r !=0 ){
			dmamap_error(sc, r, allocsize2, "tx_payload");
		}
		
	}

	/* Control virtqueue allocation - commands for the control virtqueue */
	if (vsc->sc_nvqs == 3){

		/* Control virtqueue class & command */
		r = bus_dmamap_load(vsc->requests_dmat,
				sc->sc_ctrl_cmd_dmamap,
				&sc->sc_ctrl_cmd,
				sizeof(struct virtio_net_ctrl_cmd),
				cmd_load_callback,
				sc,
				0);


		if (r != 0)
			dmamap_error(sc, r, allocsize2, "control command");

		sc->sc_ctrl_cmd_nseg = sc->sc_ctrl_nseg_temp;

		//debug("sc->sc_ctrl_segment_temp len: %d ", sc->sc_ctrl_segment_temp[0].ds_len);
		//debug("sc->sc_ctrl_cmd_nseg value: %d ", sc->sc_ctrl_cmd_nseg);


		for ( i=0; i< sc->sc_ctrl_cmd_nseg; i++){
			sc->sc_ctrl_cmd_segment[i] = sc->sc_ctrl_segment_temp[i];
			//debug("sc->sc_ctrl_cmd_segment len: %d ", sc->sc_ctrl_cmd_segment[i].ds_len);

			sc->sc_vq[CTRL_VQ].vq_desc[i].addr = sc->sc_ctrl_cmd_segment[i].ds_addr; /* Save physical address */
			debug("ctrl: sc->sc_vq[CTRL_VQ].vq_desc[%d].addr: %08X", i, sc->sc_vq[CTRL_VQ].vq_desc[i].addr);
		}

		if (sc->sc_ctrl_cmd_nseg != 1)
			debug("ctrl_cmd_segment: more than one segment");


		/* Control virtqueue status*/
		r = bus_dmamap_load(vsc->requests_dmat,
				sc->sc_ctrl_status_dmamap,
				&sc->sc_ctrl_status,
				sizeof(struct virtio_net_ctrl_status),
				cmd_load_callback,
				sc,
				0);


		if (r != 0)
			dmamap_error(sc, r, allocsize2, "control status");

		sc->sc_ctrl_status_nseg = sc->sc_ctrl_nseg_temp;


		for (i=0; i < sc->sc_ctrl_status_nseg; i++){
			sc->sc_ctrl_status_segment[i] = sc->sc_ctrl_segment_temp[i];
			//debug("seg %d sc->sc_ctrl_status_segment[i].ds_len: %08X ", i,sc->sc_ctrl_status_segment[i].ds_len);
			sc->sc_vq[CTRL_VQ].vq_desc[i].addr = sc->sc_ctrl_status_segment[i].ds_addr; /* Save physical address */
			debug("ctrl: sc->sc_vq[CTRL_VQ].vq_desc[%d].addr: %08X", i, sc->sc_vq[CTRL_VQ].vq_desc[i].addr);
		
		}
		if (sc->sc_ctrl_status_nseg != 1)
			debug("ctrl_status_segment: more than one segment");



		/* Control virtqueue rx mode command parameter */
		r = bus_dmamap_load(vsc->requests_dmat,
				sc->sc_ctrl_rx_dmamap,
				&sc->sc_ctrl_rx,
				sizeof(struct virtio_net_ctrl_rx),
				cmd_load_callback,
				sc,
				0);


		if (r != 0)
			dmamap_error(sc, r, allocsize2, "rx mode control command");

		sc->sc_ctrl_rx_nseg = sc->sc_ctrl_nseg_temp;

		for (i=0; i < sc->sc_ctrl_rx_nseg; i++){
			sc->sc_ctrl_rx_segment[i] = sc->sc_ctrl_segment_temp[i];
			
			sc->sc_vq[CTRL_VQ].vq_desc[i].addr = sc->sc_ctrl_rx_segment[i].ds_addr; /* Save physical address */
			debug("ctrl: sc->sc_vq[CTRL_VQ].vq_desc[%d]->addr: %08X", i, sc->sc_vq[CTRL_VQ].vq_desc[i].addr);
		}
		if (sc->sc_ctrl_rx_nseg != 1)
			debug("ctrl_rx_segment: more than one segment");


		/* Control virtqueue MAC filter table for unicast*/
		/* Do not load now since its length is variable */
		dmamap_create(sc,
				sc->sc_ctrl_tbl_uc_dmamap,
				allocsize2,
				"unicast MAC address filter command");

		/* Control virtqueue MAC filter table for multicast*/
		dmamap_create(sc,
				sc->sc_ctrl_tbl_mc_dmamap,
				allocsize2,
				"multicast MAC address filter command");

	}

	return 0;

err_dmamem_map:
	debug("inside err_dmamem_map\n");
	bus_dmamem_free(sc->sc_hdr_dmat, vaddr, sc->sc_hdr_dmamap);
err_none:
	debug("err_non: return -1");
	return -1;

}


/*
 * Receiving packets (rx)
 */

/* allocates and initializes a mbuf for rx */
static int
vioif_add_rx_mbuf(struct vioif_softc *sc, int i)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct mbuf *m;
	int r;

	MGETHDR(m, M_RNOWAIT, MT_DATA);
	if (m == NULL)
		return ENOBUFS;

	MCLGET(m, M_RNOWAIT);
	if ((m->m_flags & M_EXT) == 0) {
		m_freem(m);
		return ENOBUFS;
	}

	sc->sc_rx_mbufs[i] = m;
	m->m_len = m->m_pkthdr.len = m->m_ext.ext_size;

	r = bus_dmamap_load_mbuf(vsc->requests_dmat,
			sc->sc_rx_dmamaps[i],
			m,
			rx_load_mbuf_callback,
			sc,
			0);

	sc->sc_rx_nseg[i] = sc->sc_nseg_temp_rx;
	sc->sc_rx_segment[i] = sc->sc_segment_temp_rx;
	
	sc->sc_vq[RX_VQ].vq_desc[i].addr = sc->sc_rx_segment[i]->ds_addr; /* Save physical address */
	debug("sc->sc_vq[RX_VQ].vq_desc[%d]->addr = %08X ", i, sc->sc_vq[RX_VQ].vq_desc[i].addr);

	if (r) {
		m_freem(m);
		sc->sc_rx_mbufs[i] = 0;
		return r;
	}

	return 0;
}


/* vioif_free_rx_mbuf() free a mbuf for rx */
static void
vioif_free_rx_mbuf(struct vioif_softc *sc, int i)
{
	bus_dmamap_unload(sc->sc_virtio->requests_dmat, sc->sc_rx_dmamaps[i]);
	m_freem(sc->sc_rx_mbufs[i]);
	sc->sc_rx_mbufs[i] = NULL;
}


/* vioif_populate_rx_mbufs() adds mbufs for all the empty recieve slots */
static void
vioif_populate_rx_mbufs(struct vioif_softc *sc)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	int i, r, ndone = 0;
	struct virtqueue *vq = &sc->sc_vq[RX_VQ];

	for (i = 0; i < vq->vq_num; i++) {
		int slot;
		r = virtio_enqueue_prep(vsc, vq, &slot);
		//debug("slot: %d", slot);
		
		if (r == EAGAIN){
			break;
		}

		if (r != 0)
			panic("enqueue_prep for rx buffers");

		if (sc->sc_rx_mbufs[slot] == NULL) {

			r = vioif_add_rx_mbuf(sc, slot);
			if (r != 0) {
				debug("rx mbuf allocation failed, "
				       "error code %d\n", r);
				break;
			}
		}

		r = virtio_enqueue_reserve(vsc, vq, slot,
					sc->sc_rx_nseg[slot] + sc->sc_rxhdr_nseg[slot]);

		if (r != 0) {
			vioif_free_rx_mbuf(sc, slot);
			break;
		}

		bus_dmamap_sync(vsc->requests_dmat, sc->sc_rxhdr_dmamaps[slot], BUS_DMASYNC_PREREAD);
		bus_dmamap_sync(vsc->requests_dmat, sc->sc_rx_dmamaps[slot], BUS_DMASYNC_PREREAD);
		
		virtio_enqueue(vsc, vq, slot, sc->sc_rxhdr_segment[slot], sc->sc_rxhdr_nseg[slot], sc->sc_rxhdr_dmamaps[slot], false);
		virtio_enqueue(vsc, vq, slot, sc->sc_rx_segment[slot], sc->sc_rx_nseg[slot], sc->sc_rx_dmamaps[slot], false);

		virtio_enqueue_commit(vsc, vq, slot, false);
		ndone++;
	}
	if (ndone > 0)
		virtio_enqueue_commit(vsc, vq, -1, true);

}

/* vioif_rx_deq() dequeues recieved packets */
static int
vioif_rx_deq(struct vioif_softc *sc)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = &sc->sc_vq[RX_VQ];
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	struct mbuf *m;
	int r = 0;
	int slot, len;

	while(virtio_dequeue(vsc, vq, &slot, &len) == 0){
		debug("while");
		len -= sizeof(struct virtio_net_hdr);
		r = 1;
		bus_dmamap_sync(vsc->requests_dmat, sc->sc_rxhdr_dmamaps[slot],BUS_DMASYNC_POSTREAD);
		bus_dmamap_sync(vsc->requests_dmat, sc->sc_rx_dmamaps[slot],BUS_DMASYNC_POSTREAD);

		m = sc->sc_rx_mbufs[slot];
		KKASSERT(m != NULL);

		bus_dmamap_unload(vsc->requests_dmat, sc->sc_rx_dmamaps[slot]);
		sc->sc_rx_mbufs[slot] = 0;
		virtio_dequeue_commit(vsc, vq, slot);

		m->m_pkthdr.rcvif = ifp;
		m->m_len = m->m_pkthdr.len = len;
		ifp->if_ipackets++;

#if NBPFILTER > 0
		if (ifp->if_bpf)
			bpf_mtap(ifp->if_bpf, m);
#endif /* NBPFILTER > 0 */

		(*ifp->if_input)(ifp, m);
		debug("end while");
	}

	return r;
}


/*
 * rx interrupt
 *
 */

static int
vioif_rx_vq_done(struct virtqueue *vq)
{
	debug("call");
	struct virtio_softc *vsc = vq->vq_owner;
	struct vioif_softc *sc = device_get_softc(vsc->sc_child);
	int r = 0;

	r = vioif_rx_deq(sc);

	taskqueue_enqueue(sc->sc_rx_tq, &sc->sc_rxtask);

	return r;
}


static void
vioif_rx_task(void *arg, int pending)
{
	device_t dev = arg;
	struct vioif_softc *sc = device_get_softc(dev);

	vioif_populate_rx_mbufs(sc);

}

/* vioif_rx_drain() frees all the mbufs, and is called from if_stop(disable) */

static void
vioif_rx_drain(struct vioif_softc *sc)
{
	struct virtqueue *vq = &sc->sc_vq[RX_VQ];
	int i;

	for (i = 0; i < vq->vq_num; i++){

		if (sc->sc_rx_mbufs[i] ==  NULL)
			continue;
		vioif_free_rx_mbuf(sc, i);
	}
}


/*
 * Transmission implementation
 */

static int
vioif_tx_vq_done(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct vioif_softc *sc = device_get_softc(vsc->sc_child);
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;

	struct mbuf *m;
	int r = 0;
	int slot, len;

	while (virtio_dequeue(vsc, vq, &slot, &len) == 0){
		r++;
		bus_dmamap_sync(vsc->requests_dmat, sc->sc_txhdr_dmamaps[slot], BUS_DMASYNC_POSTWRITE);
		bus_dmamap_sync(vsc->requests_dmat, sc->sc_tx_dmamaps[slot], BUS_DMASYNC_POSTWRITE);

		m = sc->sc_tx_mbufs[slot];
		bus_dmamap_unload(vsc->requests_dmat, sc->sc_tx_dmamaps[slot]);

		sc->sc_tx_mbufs[slot] = 0;
		virtio_dequeue_commit(vsc, vq, slot);

		ifp->if_opackets++;
		m_freem(m);
	}

	if (r)
		ifp->if_flags &= ~IFF_OACTIVE;
	return r;
}


/* vioif_tx_drain frees all the mbufs already put on vq */
static void
vioif_tx_drain(struct vioif_softc *sc)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = &sc->sc_vq[TX_VQ];
	int i;

	for (i = 0; i < vq->vq_num; i++) {

		if (sc->sc_tx_mbufs[i] == NULL)
			continue;

		bus_dmamap_unload(vsc->requests_dmat, sc->sc_tx_dmamaps[i]);
		m_freem(sc->sc_tx_mbufs[i]);
		sc->sc_tx_mbufs[i] = NULL;
	}
}



/* Control virtqueue functions
 *
 * If IFF_PROMISC is requested, set promiscuous mode.
 * If multicast filter is small enough (<=MAXENTRIES), set rx filter
 * If large multicast filter exists, use ALLMULTI.
 *
 *
 * If setting rx filter fails, fall back to ALLMULTI mode.
 * If ALLMULTI fails, fall back to PROMISC mode.
 */


/* issue a VIRTIO_NET_CTRL_RX class command and wait for completion */
static int
vioif_ctrl_rx(struct vioif_softc *sc, int cmd, bool onoff)
{
	debug("call");

	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = &sc->sc_vq[CTRL_VQ];
	int r, slot;

	if (vsc->sc_nvqs < 3)
		return ENOTSUP;

	lockmgr(&sc->sc_ctrl_wait_lock, LK_EXCLUSIVE);
	debug("lockmgr LK_EXCLUSIVE\n");

	while(sc->sc_ctrl_inuse != ISFREE) {
		debug("SLEEP");
		cv_wait(&sc->sc_ctrl_wait, &sc->sc_ctrl_wait_lock);
		debug("OUT OF SLEEP");
	}

	sc->sc_ctrl_inuse = INUSE;

	lockmgr(&sc->sc_ctrl_wait_lock, LK_RELEASE);
	debug("lockmgr LK_RELEASE\n");

	sc->sc_ctrl_cmd->class = (uint8_t) VIRTIO_NET_CTRL_RX;
	sc->sc_ctrl_cmd->command = (uint8_t) cmd;
	sc->sc_ctrl_rx->onoff = (uint8_t) onoff;

	bus_dmamap_sync(vsc->requests_dmat, sc->sc_ctrl_cmd_dmamap,BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(vsc->requests_dmat, sc->sc_ctrl_rx_dmamap,BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(vsc->requests_dmat, sc->sc_ctrl_status_dmamap, BUS_DMASYNC_PREREAD);

	debug("after bus_dmamap_sync");

	debug("ctrl: vq_desc->addr: %08X", sc->sc_vq[CTRL_VQ].vq_desc->addr);

	r = virtio_enqueue_prep(vsc, vq, &slot);
	
	if (r != 0)
		debug("%s: control virtqueue busy!?\n", device_get_name(sc->dev));

	r = virtio_enqueue_reserve(vsc, vq, slot, 3);

	debug("after virtio_enqueue_reserve");

	if (r != 0)
		debug("%s: control vq busy!?\n", device_get_name(sc->dev));
		
	virtio_enqueue(vsc, vq, slot,
			sc->sc_ctrl_cmd_segment,
			sc->sc_ctrl_cmd_nseg,
			sc->sc_ctrl_cmd_dmamap,
			true);

	virtio_enqueue(vsc, vq, slot,
			sc->sc_ctrl_rx_segment,
			sc->sc_ctrl_rx_nseg,
			sc->sc_ctrl_rx_dmamap,
			true);

	virtio_enqueue(vsc, vq, slot,
			sc->sc_ctrl_status_segment,
			sc->sc_ctrl_status_nseg,
			sc->sc_ctrl_status_dmamap,
			false);



	debug("ctrl: vq_desc->addr: %08X", sc->sc_vq[CTRL_VQ].vq_desc->addr);

	virtio_enqueue_commit(vsc, vq, slot, true);

	/* wait for done */

	lockmgr(&sc->sc_ctrl_wait_lock, LK_EXCLUSIVE);

	debug("sc_ctrl_inuse %08X, = %d", &sc->sc_ctrl_inuse, sc->sc_ctrl_inuse);
	while (sc->sc_ctrl_inuse != DONE) {
		debug("SLEEP");
		cv_wait(&sc->sc_ctrl_wait, &sc->sc_ctrl_wait_lock);
		debug("OUT OF SLEEP");
	}

	lockmgr(&sc->sc_ctrl_wait_lock, LK_RELEASE);

	bus_dmamap_sync(vsc->requests_dmat, sc->sc_ctrl_cmd_dmamap, BUS_DMASYNC_POSTWRITE);
	bus_dmamap_sync(vsc->requests_dmat, sc->sc_ctrl_rx_dmamap, BUS_DMASYNC_POSTWRITE);
	bus_dmamap_sync(vsc->requests_dmat, sc->sc_ctrl_status_dmamap, BUS_DMASYNC_POSTREAD);


	if (sc->sc_ctrl_status->ack == VIRTIO_NET_OK)
		r = 0;
	else {
		debug("failed setting rx mode\n");
		r = EIO;
	}

	debug("after if");

	lockmgr(&sc->sc_ctrl_wait_lock, LK_EXCLUSIVE);
	sc->sc_ctrl_inuse = ISFREE;
	cv_signal(&sc->sc_ctrl_wait);
	lockmgr(&sc->sc_ctrl_wait_lock, LK_RELEASE);


	return r;
}

/*
 * Set on/off promiscuous mode for the virtio network device (the kernel/CPU
 * will receive all network traffic)
 */

/* We need interrupt to make promiscuous mode off */
static void
vioif_deferred_init(device_t dev)
{
	struct vioif_softc *sc = device_get_softc(dev);

	wakeup(sc);
	return;
}

static void
vioif_set_promisc_init(void *arg)
{
	device_t dev = arg;
	struct vioif_softc *sc = device_get_softc(dev);
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	int r;

	debug("call");
	KKASSERT(sc != NULL);

	/* Let _attach know that we are ready */
	wakeup(curthread);

	/* and now sleep until we are supposed to the the promisc init */
	tsleep(sc, 0, "virtpromisc", 0);

	r = vioif_ctrl_rx(sc, VIRTIO_NET_CTRL_RX_PROMISC, false);

	if (r != 0)
		debug("resetting promisc mode failed, "
					 "error code %d\n", r);
	else
		ifp->if_flags &= ~IFF_PROMISC;

	sc->sc_init = 1; /* the job of deferred init is done; we can execute others interrupts*/

	lwkt_exit();
}

static int
vioif_set_promisc(struct vioif_softc *sc, bool onoff)
{
	int r;
	debug("call");

	r = vioif_ctrl_rx(sc, VIRTIO_NET_CTRL_RX_PROMISC, onoff);

	return r;
}

/*
 * All multicast mode ?
 * */

static int
vioif_set_allmulti(struct vioif_softc *sc, bool onoff)
{
	int r;

	r = vioif_ctrl_rx(sc, VIRTIO_NET_CTRL_RX_ALLMULTI, onoff);
	return r;
}

/* issue VIRTIO_NET_CTRL_MAC_TABLE_SET command and wait for completion */
static int
vioif_set_rx_filter(struct vioif_softc *sc)
{
	// filter already set in sc_trl_mac_tbl
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = &sc->sc_vq[CTRL_VQ];
	int r, slot, i;


	if (vsc->sc_nvqs < 3)
		return ENOTSUP;
		

	lockmgr(&sc->sc_ctrl_wait_lock, LK_EXCLUSIVE);
	
	while (sc->sc_ctrl_inuse != ISFREE) {
		debug("SLEEP");
		cv_wait(&sc->sc_ctrl_wait, &sc->sc_ctrl_wait_lock);
		debug("OUT OF SLEEP");
	}
	sc->sc_ctrl_inuse = INUSE;
	lockmgr(&sc->sc_ctrl_wait_lock, LK_RELEASE);

	sc->sc_ctrl_cmd->class = VIRTIO_NET_CTRL_MAC;
	sc->sc_ctrl_cmd->command = VIRTIO_NET_CTRL_MAC_TABLE_SET;

	r = bus_dmamap_load(vsc->requests_dmat,
			sc->sc_ctrl_tbl_uc_dmamap,
			&sc->sc_ctrl_mac_tbl_uc,
			(sizeof(struct virtio_net_ctrl_mac_tbl)
			+ ETHER_ADDR_LEN * sc->sc_ctrl_mac_tbl_uc->nentries),
			cmd_load_callback,
			sc,
			0);

	if (r) {
		debug("control command dmamap load failed, " "error code %d\n", r);
		goto out;
	}

	sc->sc_ctrl_uc_nseg = sc->sc_ctrl_nseg_temp;

	for (i=0; i < sc->sc_ctrl_uc_nseg; i++){
		sc->sc_ctrl_uc_segment[i] = sc->sc_ctrl_segment_temp[i];
		sc->sc_vq[CTRL_VQ].vq_desc[i].addr = sc->sc_ctrl_uc_segment[i].ds_addr; /* Save physical address */
		debug("ctrl: sc->sc_vq[CTRL_VQ].vq_desc[%d]->addr: %08X", i, sc->sc_vq[CTRL_VQ].vq_desc[i].addr);
	}

	r = bus_dmamap_load(vsc->requests_dmat,
			sc->sc_ctrl_tbl_mc_dmamap,
			&sc->sc_ctrl_mac_tbl_mc,
			(sizeof(struct virtio_net_ctrl_mac_tbl)
			+ ETHER_ADDR_LEN * sc->sc_ctrl_mac_tbl_mc->nentries),
			cmd_load_callback,
			sc,
			0);

	if (r) {
		debug("control command dmamap load failed, " "error code %d\n", r);
		bus_dmamap_unload(vsc->requests_dmat, sc->sc_ctrl_tbl_uc_dmamap);
		goto out;
	}

	sc->sc_ctrl_mc_nseg = sc->sc_ctrl_nseg_temp;

	for (i=0; i < sc->sc_ctrl_mc_nseg; i++){
		sc->sc_ctrl_mc_segment[i] = sc->sc_ctrl_segment_temp[i];
		
		sc->sc_vq[CTRL_VQ].vq_desc[i].addr = sc->sc_ctrl_mc_segment[i].ds_addr; /* Save physical address */
		debug("ctrl: sc->sc_vq[CTRL_VQ].vq_desc[%d]->addr: %08X", i, sc->sc_vq[CTRL_VQ].vq_desc[i].addr);
		
	}



	bus_dmamap_sync(vsc->requests_dmat, sc->sc_ctrl_cmd_dmamap,BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(vsc->requests_dmat, sc->sc_ctrl_tbl_uc_dmamap,BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(vsc->requests_dmat, sc->sc_ctrl_tbl_mc_dmamap,BUS_DMASYNC_PREWRITE);
	bus_dmamap_sync(vsc->requests_dmat, sc->sc_ctrl_status_dmamap,BUS_DMASYNC_PREREAD);


	debug("ctrl: vq_desc->addr: %08X", sc->sc_vq[CTRL_VQ].vq_desc->addr);

	r = virtio_enqueue_prep(vsc, vq, &slot);

	if (r != 0)
		debug("control vq busy!?\n");

	r = virtio_enqueue_reserve(vsc, vq, slot, 4);

	if (r != 0)
		debug("control vq busy!?\n");

	virtio_enqueue(vsc, vq, slot, sc->sc_ctrl_cmd_segment, sc->sc_ctrl_cmd_nseg, sc->sc_ctrl_cmd_dmamap, true);
	virtio_enqueue(vsc, vq, slot, sc->sc_ctrl_uc_segment, sc->sc_ctrl_uc_nseg, sc->sc_ctrl_tbl_uc_dmamap, false);
	virtio_enqueue(vsc, vq, slot, sc->sc_ctrl_mc_segment, sc->sc_ctrl_mc_nseg, sc->sc_ctrl_tbl_mc_dmamap, false);
	virtio_enqueue(vsc, vq, slot, sc->sc_ctrl_status_segment, sc->sc_ctrl_status_nseg, sc->sc_ctrl_status_dmamap, true);

	debug("ctrl: vq_desc->addr: %08X", sc->sc_vq[CTRL_VQ].vq_desc->addr);

	virtio_enqueue_commit(vsc, vq, slot, true);

	// wait for done

	lockmgr(&sc->sc_ctrl_wait_lock, LK_EXCLUSIVE);
	while (sc->sc_ctrl_inuse != DONE) {
		debug("SLEEP");
		cv_wait(&sc->sc_ctrl_wait, &sc->sc_ctrl_wait_lock);
		debug("OUT OF SLEEP");
	}
	lockmgr(&sc->sc_ctrl_wait_lock, LK_RELEASE);

	// already dequeueued
	bus_dmamap_sync(vsc->requests_dmat, sc->sc_ctrl_cmd_dmamap, BUS_DMASYNC_POSTWRITE);
	bus_dmamap_sync(vsc->requests_dmat, sc->sc_ctrl_tbl_uc_dmamap, BUS_DMASYNC_POSTWRITE);
	bus_dmamap_sync(vsc->requests_dmat, sc->sc_ctrl_tbl_mc_dmamap, BUS_DMASYNC_POSTWRITE);
	bus_dmamap_sync(vsc->requests_dmat, sc->sc_ctrl_status_dmamap, BUS_DMASYNC_POSTREAD);

	bus_dmamap_unload(vsc->requests_dmat, sc->sc_ctrl_tbl_uc_dmamap);
	bus_dmamap_unload(vsc->requests_dmat, sc->sc_ctrl_tbl_mc_dmamap);

	if (sc->sc_ctrl_status->ack == VIRTIO_NET_OK)
		r = 0;
	else {
		debug("failed setting rx filter\n");
		r = EIO;
	}

out:
	lockmgr(&sc->sc_ctrl_wait_lock, LK_EXCLUSIVE);
	sc->sc_ctrl_inuse = ISFREE;
	cv_signal(&sc->sc_ctrl_wait);
	lockmgr(&sc->sc_ctrl_wait_lock, LK_RELEASE);

	return r;

}

static int
vioif_rx_filter(struct vioif_softc *sc)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;

	struct ifmultiaddr *ifma; 	//Multicast address structure

	int nentries;
	int promisc = 0, allmulti = 0, rxfilter = 0;
	int r;
	
	debug("sc_ctrl_inuse %08X, = %d", &sc->sc_ctrl_inuse, sc->sc_ctrl_inuse);

	if (vsc->sc_nvqs < 3) {	//no ctrl vq; always promisc
		ifp->if_flags |= IFF_PROMISC;
		return 0;
	}

	if (ifp->if_flags & IFF_PROMISC) {
		promisc = 1;
		goto set;
	}

	nentries = -1;
	ifma = TAILQ_FIRST(&ifp->if_multiaddrs); // first address in the queue

	while (nentries++, ifma != NULL) {
		debug("while");
		if (nentries >= VIRTIO_NET_CTRL_MAC_MAXENTRIES) {
			allmulti = 1;
			goto set;
		}


		memcpy(sc->sc_ctrl_mac_tbl_mc->macs[nentries],
				ifma,
				ETHER_ADDR_LEN);
		//XXX: what is this? this does nothing!
		ifma = TAILQ_NEXT(ifma, ifma_link);

	}
	rxfilter = 1;

set:
	debug("sc_ctrl_inuse %08X, = %d", &sc->sc_ctrl_inuse, sc->sc_ctrl_inuse);
	if (rxfilter) {
		sc->sc_ctrl_mac_tbl_uc->nentries = 0;
		sc->sc_ctrl_mac_tbl_mc->nentries = nentries;
		r = vioif_set_rx_filter(sc);

		if (r != 0) {
			rxfilter = 0;
			allmulti = 1; // fallback
		}
	} else {
		// remove rx filter
		sc->sc_ctrl_mac_tbl_uc->nentries = 0;
		sc->sc_ctrl_mac_tbl_mc->nentries = 0;
		r = vioif_set_rx_filter(sc);
		// what to do on failure?
	}

	if (allmulti) {
		r = vioif_set_allmulti(sc, true);

		if (r != 0) {
			allmulti = 0;
			promisc = 1; // fallback
		}

	} else {
		r = vioif_set_allmulti(sc, false);
		// what to do on failure?
	}

	if (promisc) {
		r = vioif_set_promisc(sc, true);
	} else {
		r = vioif_set_promisc(sc, false);
	}

	return r;

}


/* Control virtqueue interrupt;  */

static int
vioif_ctrl_vq_done(struct virtqueue *vq)
{
	debug("call");
	struct virtio_softc *vsc = vq->vq_owner;
	struct vioif_softc *sc = device_get_softc(vsc->sc_child);
	int r, slot;

	r = virtio_dequeue(vsc, vq, &slot, NULL);

	if (r == ENOENT)
		return 0;

	//debug("call dequeue_commit");
	r = virtio_dequeue_commit(vsc, vq, slot);

	if (r != 0){
		debug("complete dequeue failed");
		return 1;
	}

	lockmgr(&sc->sc_ctrl_wait_lock, LK_EXCLUSIVE);
	debug("lk_exclusive");

	sc->sc_ctrl_inuse = DONE;
	debug("sc_ctrl_inuse %08X, = %d", &sc->sc_ctrl_inuse, sc->sc_ctrl_inuse);

	cv_signal(&sc->sc_ctrl_wait);
	debug("wakeup thread");
	lockmgr(&sc->sc_ctrl_wait_lock, LK_RELEASE);
	debug("lk_release");

	return 1;
}


static int
vioif_probe(device_t dev)
{
	
	device_t pdev = device_get_parent(dev);

	if(pci_read_config(pdev,PCIR_SUBDEV_0,2) == PCI_PRODUCT_VIRTIO_NETWORK) {
		debug("parent:%p is net\n", pdev);
	} else {
		debug("parent:%p is not net\n", pdev);
		return 1;
	}

	return 0;

}


static int
vioif_attach(device_t dev)
{

	struct vioif_softc *sc = device_get_softc(dev);
	device_t pdev = device_get_parent(dev);
	struct virtio_softc *vsc = device_get_softc(pdev);
	uint32_t features;
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	int error;

	sc->dev = dev;
	sc->sc_virtio = vsc;

	vsc->sc_vqs = &sc->sc_vq[RX_VQ];
	vsc->sc_child = dev;

	vsc->sc_config_change = 0; /* keep it?*/

	lwkt_serialize_init(&sc->sc_serializer);

	features = virtio_negotiate_features(vsc,
						(VIRTIO_NET_F_MAC |
						 VIRTIO_NET_F_STATUS |
						 VIRTIO_NET_F_CTRL_VQ |
						 VIRTIO_NET_F_CTRL_RX |
						 VIRTIO_F_NOTIFY_ON_EMPTY));
		if (features & VIRTIO_NET_F_MAC) {
			sc->sc_mac[0] = virtio_read_device_config_1(vsc,
							    VIRTIO_NET_CONFIG_MAC+0);
			sc->sc_mac[1] = virtio_read_device_config_1(vsc,
							    VIRTIO_NET_CONFIG_MAC+1);
			sc->sc_mac[2] = virtio_read_device_config_1(vsc,
							    VIRTIO_NET_CONFIG_MAC+2);
			sc->sc_mac[3] = virtio_read_device_config_1(vsc,
							    VIRTIO_NET_CONFIG_MAC+3);
			sc->sc_mac[4] = virtio_read_device_config_1(vsc,
							    VIRTIO_NET_CONFIG_MAC+4);
			sc->sc_mac[5] = virtio_read_device_config_1(vsc,
							    VIRTIO_NET_CONFIG_MAC+5);
		} else {
			/* code stolen from sys/net/if_tap.c */
			struct timeval tv;
			uint32_t ui;
			getmicrouptime(&tv);
			ui = (tv.tv_sec ^ tv.tv_usec) & 0xffffff;
			memcpy(sc->sc_mac+3, (uint8_t *)&ui, 3);
			bus_space_write_1(vsc->sc_iot, vsc->sc_ioh,
						     VIRTIO_NET_CONFIG_MAC+0,
						     sc->sc_mac[0]);
			bus_space_write_1(vsc->sc_iot, vsc->sc_ioh,
						     VIRTIO_NET_CONFIG_MAC+1,
						     sc->sc_mac[1]);
			bus_space_write_1(vsc->sc_iot, vsc->sc_ioh,
						     VIRTIO_NET_CONFIG_MAC+2,
						     sc->sc_mac[2]);
			bus_space_write_1(vsc->sc_iot, vsc->sc_ioh,
						     VIRTIO_NET_CONFIG_MAC+3,
						     sc->sc_mac[3]);
			bus_space_write_1(vsc->sc_iot, vsc->sc_ioh,
						     VIRTIO_NET_CONFIG_MAC+4,
						     sc->sc_mac[4]);
			bus_space_write_1(vsc->sc_iot, vsc->sc_ioh,
						     VIRTIO_NET_CONFIG_MAC+5,
						     sc->sc_mac[5]);
		}


	kprintf("Attach started ->> %s\n",__FUNCTION__);


	/* Virtqueue allocation for the rx queue. */
	error = virtio_alloc_vq(vsc,&sc->sc_vq[RX_VQ],0,
				MCLBYTES+sizeof(struct virtio_net_hdr),2,
				"rx vq");

	if (error != 0)	{
		debug("Virtqueue allocation for rx failed\n");
		goto err;
	}

	vsc->sc_nvqs = 1;
	sc->sc_vq[RX_VQ].vq_done = vioif_rx_vq_done; /* rx interrupt*/


	/* Virtqueue allocation for the tx queue. */
	error = virtio_alloc_vq(vsc, &sc->sc_vq[TX_VQ], 1,
		    	(sizeof(struct virtio_net_hdr)+ (ETHER_MAX_LEN - ETHER_HDR_LEN)),
		    	 VIRTIO_NET_TX_MAXNSEGS + 1,
		    	"tx vq");

	if (error != 0){
		debug("Virtqueue allocation for tx failed\n");
		goto err;
	}
	vsc->sc_nvqs = 2;
	sc->sc_vq[TX_VQ].vq_done = vioif_tx_vq_done; /* tx interrupt*/

	virtio_start_vq_intr(vsc, &sc->sc_vq[RX_VQ]);
	virtio_stop_vq_intr(vsc, &sc->sc_vq[RX_VQ]);

	/* Virtqueue allocation for the ctrl queue */
	if ((features & VIRTIO_NET_F_CTRL_VQ) && (features & VIRTIO_NET_F_CTRL_RX)){ /* rx & ctrl queues */

		error = virtio_alloc_vq(vsc,
				&sc->sc_vq[CTRL_VQ], 2,
			    VIRTIO_PAGE_SIZE, 1,
			    "control vq");

		if (error != 0){
			debug("Virtqueue allocation for control failed\n");
			goto err;
		}

		vsc->sc_nvqs = 3;
		sc->sc_ctrl_inuse = ISFREE;

		sc->sc_vq[CTRL_VQ].vq_done = vioif_ctrl_vq_done;
		virtio_start_vq_intr(vsc, &sc->sc_vq[CTRL_VQ]);
	}

	/* Initialize the lock to deal with interrupts for ctrl packets
	 * - allow recursive locks */
	cv_init(&sc->sc_ctrl_wait, "ctrl_vq");
	lockinit(&sc->sc_ctrl_wait_lock, "ctrl lock", 0, LK_CANRECURSE);

	/* Initialize the lock to deal with interrupts for the rx packets
	 *  - allow recursive locks */
	lockinit(&sc->sc_lock, "vioif lock", 0, LK_CANRECURSE);

	/* Memory allocation for the control queue (for virtio_softc) */
	if (vioif_alloc_mems(sc) < 0){
		debug("vioif_alloc_mems(sc) failed !\n");
		goto err;
	}



	/* There is no MII or real PHY */
	ifmedia_init(&sc->sc_ifm, 0 /*don't care mask*/, 
		ifm_change_callback, ifm_status_callback);

	ifmedia_add(&sc->sc_ifm, IFM_ETHER|IFM_1000_T, 0, NULL);
	ifmedia_set(&sc->sc_ifm, IFM_ETHER|IFM_1000_T);

	/* Interface for the device switch */
	kprintf("\ndevice name %s\n", device_get_name(dev));
	if_initname(ifp, device_get_name(dev), device_get_unit(dev));

	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_start = vioif_start;
	ifp->if_ioctl = vioif_ioctl;
	ifp->if_init = vioif_init;
	ifp->if_mtu  = ETHERMTU;
	ifp->if_capabilities = 0;
	ifp->if_capenable = ifp->if_capabilities;
	ifp->if_watchdog = vioif_watchdog;

	ifq_set_maxlen(&ifp->if_snd, 1);
	ifq_set_ready(&ifp->if_snd);

	/* Attach the interface */
	ether_ifattach(ifp, sc->sc_mac, &sc->sc_serializer);
	debug("ether_ifattach");


	/* create a taskqueue for rx*/
	sc->sc_rx_tq = taskqueue_create("rx_taskq", M_INTWAIT,
			taskqueue_thread_enqueue, &sc->sc_rx_tq);

	if (sc->sc_rx_tq == NULL){
		debug("could not create taskqueue");
		ether_ifdetach(ifp);
		goto err;
	}

	/* create one thread */
	taskqueue_start_threads(&sc->sc_rx_tq, 1, TDPRI_KERN_DAEMON, -1, "%s taskq", ifp->if_xname);

	/* create rx task structure */
	TASK_INIT(&sc->sc_rxtask, 0, vioif_rx_task, sc);


	/* spinlock used in vioif_ioctl*/
	spin_init(&sc->lock_io);
	lwkt_serialize_enter(&sc->sc_serializer);

	virtio_set_status(vsc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);

	lwkt_serialize_exit(&sc->sc_serializer);

	/* put at the end of the attach routine, so it doesn't block its execution*/
	if (vsc->sc_nvqs == 3){

		/* Set promiscuous mode off at starting. Needs interrupt */
		error =  lwkt_create(vioif_set_promisc_init,
				sc->dev,
				&sc->sc_promisc_td,
				NULL, 0, 0,
				"vioif_set_promisc");

		if (error){
			debug("Creation of vioif_set_promisc_init thread failed\n");
			taskqueue_free(sc->sc_rx_tq);
			sc->sc_rx_tq = NULL;
			ether_ifdetach(ifp);
			goto err;
		}

		debug("before tsleep(sc_promisc_td)");
		tsleep(sc->sc_promisc_td, 0, "sc_promisc_td", 0);
		debug("after tsleep(sc_promisc_td)");

		vioif_deferred_init(dev);
	}
    return 0;

err:
	if (vsc->sc_nvqs == 3) {
		virtio_free_vq(vsc, &sc->sc_vq[CTRL_VQ]);
		cv_destroy(&sc->sc_ctrl_wait);
		lockuninit(&sc->sc_ctrl_wait_lock);
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
vioif_detach(device_t dev)
{
	kprintf("%s\n",__FUNCTION__);
	struct vioif_softc *sc = device_get_softc(dev);
	device_t pdev = device_get_parent(sc->dev);
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	struct virtio_softc *vsc = device_get_softc(pdev);

	taskqueue_drain(sc->sc_rx_tq, &sc->sc_rxtask);
	taskqueue_free(sc->sc_rx_tq);

	ether_ifdetach(ifp);

	cv_destroy(&sc->sc_ctrl_wait);
	lockuninit(&sc->sc_ctrl_wait_lock);

	vioif_destroy_vq(sc, vsc, RX_VQ, false); /* destroy rx vq */
	vioif_destroy_vq(sc, vsc, TX_VQ, false); /* destroy tx vq */
	vioif_destroy_vq(sc, vsc, CTRL_VQ, false); /* destroy ctrl vq */

	/* Control virtqueue class & command dmamap destroy */
	bus_dmamap_unload(vsc->requests_dmat, sc->sc_ctrl_cmd_dmamap);
	bus_dmamap_destroy(vsc->requests_dmat, sc->sc_ctrl_cmd_dmamap);


	/* Mac address filtering dmamap destroy*/
	bus_dmamap_unload(vsc->requests_dmat, sc->sc_ctrl_tbl_mc_dmamap);
	bus_dmamap_destroy(vsc->requests_dmat, sc->sc_ctrl_tbl_mc_dmamap);
	bus_dmamap_unload(vsc->requests_dmat, sc->sc_ctrl_tbl_uc_dmamap);
	bus_dmamap_destroy(vsc->requests_dmat, sc->sc_ctrl_tbl_uc_dmamap);

	/* Control rx dmamap destroy*/
	bus_dmamap_unload(vsc->requests_dmat, sc->sc_ctrl_rx_dmamap);
	bus_dmamap_destroy(vsc->requests_dmat, sc->sc_ctrl_rx_dmamap);

	/* Control status dmamap destroy*/
	bus_dmamap_unload(vsc->requests_dmat, sc->sc_ctrl_status_dmamap);
	bus_dmamap_destroy(vsc->requests_dmat, sc->sc_ctrl_status_dmamap);

	if (sc->sc_rxhdr_dmamaps) {
		bus_dmamem_free(vsc->requests_dmat,
				&sc->sc_vq[RX_VQ].vq_desc->addr,
				*sc->sc_rxhdr_dmamaps);
		sc->sc_rxhdr_dmamaps = 0;
	}

	bus_dma_tag_destroy(vsc->requests_dmat);

	virtio_reset(vsc);

	kfree(sc->sc_rxhdr_nseg, M_DEVBUF);
	kfree(sc->sc_txhdr_nseg, M_DEVBUF);

	kfree(sc->sc_rx_nseg, M_DEVBUF);
	kfree(sc->sc_tx_nseg, M_DEVBUF);

	kfree(sc->sc_rxhdr_segment, M_DEVBUF);
	kfree(sc->sc_txhdr_segment, M_DEVBUF);

	kfree(sc->sc_rx_segment, M_DEVBUF);
	kfree(sc->sc_tx_segment, M_DEVBUF);


	/*unload and free virtqueue*/

	vioif_destroy_vq(sc, vsc, RX_VQ, true); /* destroy rx vq */
	vioif_destroy_vq(sc, vsc, TX_VQ, true); /* destroy tx vq */
	vioif_destroy_vq(sc, vsc, CTRL_VQ, true); /* destroy ctrl vq */

	/* free net-related stuff */

	return 0;
}

/* Unload and free &sc->sc_vq[numq] */
static int
vioif_destroy_vq( struct vioif_softc *sc, struct virtio_softc *vsc, int numq, bool go_on){

	struct virtqueue *vq = &vsc->sc_vqs[numq];
	int i;

	if (!go_on){
		for (i=0; i<sc->sc_vq[numq].vq_num; i++){

			/* rx header dmamap destroy */
			bus_dmamap_unload(vsc->requests_dmat, sc->sc_arrays[i]);
			bus_dmamap_destroy(vsc->requests_dmat, sc->sc_arrays[i]);

			/* rx dmamap destroy */
			bus_dmamap_unload(vsc->requests_dmat, sc->sc_rx_dmamaps[i]);
			bus_dmamap_destroy(vsc->requests_dmat, sc->sc_rx_dmamaps[i]);


			/*tx header destroy */
			bus_dmamap_unload(vsc->requests_dmat, sc->sc_txhdr_dmamaps[i]);
			bus_dmamap_destroy(vsc->requests_dmat, sc->sc_txhdr_dmamaps[i]);

			/* tx dmamap destroy */
			bus_dmamap_unload(vsc->requests_dmat, sc->sc_tx_dmamaps[i]);
			bus_dmamap_destroy(vsc->requests_dmat, sc->sc_tx_dmamaps[i]);
		}

	} else {

		/*unload and free virtqueue*/

		virtio_free_vq(vsc, vq);

		bus_dmamap_unload(vq->vq_dmat, vq->vq_dmamap);
		bus_dmamem_free(vq->vq_dmat, vq->vq_vaddr, vq->vq_dmamap);
		bus_dma_tag_destroy(vq->vq_dmat);
		memset(vq, 0, sizeof(*vq));

	}

	return 0;
}

static device_method_t virtio_net_methods[] = {
	DEVMETHOD(device_probe,         vioif_probe),
	DEVMETHOD(device_attach,        vioif_attach),
	DEVMETHOD(device_detach,        vioif_detach),
	{ 0, 0 }
};

static driver_t virtio_net_driver = {
	"virtio_net",
	virtio_net_methods,
	sizeof(struct vioif_softc),
};

static devclass_t virtio_net_devclass;

DRIVER_MODULE(virtio_net, virtiobus, virtio_net_driver, virtio_net_devclass, 0, 0);
MODULE_DEPEND(virtio_net, virtiobus, 0, 0, 0);
