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
 *
 */

#ifndef _VIRTIONET_H_
#define _VIRTIONET_H_

#include "virtiovar.h"
#include "virtioreg.h"

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

#define VIRTIO_NET_TX_MAXNSEGS		(16) /* XXX */
#define VIRTIO_NET_CTRL_MAC_MAXENTRIES	(64) /* XXX */


/* Receiving, transmitting and control virtqueue */
#define RX_VQ 0
#define TX_VQ 1
#define CTRL_VQ 2

#define NDEVNAMES	(sizeof(virtio_device_name)/sizeof(char*))
#define MINSEG_INDIRECT     2 /* use indirect if nsegs >= this value */


/* Control virtqueue command */
struct virtio_net_ctrl_cmd {
	uint8_t	class;
	uint8_t	command;
} __packed;

struct virtio_net_ctrl_status {
	uint8_t	ack;
} __packed;
#define VIRTIO_NET_OK			0
#define VIRTIO_NET_ERR			1


/* Setting promiscuous mode */
struct virtio_net_ctrl_rx {
	uint8_t	onoff;
} __packed;

#define VIRTIO_NET_CTRL_RX		0
#define VIRTIO_NET_CTRL_RX_PROMISC	0
#define VIRTIO_NET_CTRL_RX_ALLMULTI	1


/* MAC address filtering */
struct virtio_net_ctrl_mac_tbl {
	uint32_t nentries;
	uint8_t macs[][ETHER_ADDR_LEN];
} __packed;

#define VIRTIO_NET_CTRL_MAC		1
#define VIRTIO_NET_CTRL_MAC_TABLE_SET	0


/* VLAN filtering */
struct virtio_net_ctrl_vlan {
	uint16_t id;
} __packed;

#define VIRTIO_NET_CTRL_VLAN		2
#define VIRTIO_NET_CTRL_VLAN_ADD	0
#define VIRTIO_NET_CTRL_VLAN_DEL	1



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

struct vioif_softc {

	device_t 		dev;
	struct 			virtio_softc *sc_virtio;
	struct			virtqueue sc_vq[3]; /* 3 virtqueues : rx, tx & ctrl */

	int 			sc_readonly;
	uint32_t 		sc_features;
	int 			maxxfersize;

	short 			sc_ifflags;
	uint8_t 		sc_mac[ETHER_ADDR_LEN];
	struct arpcom 	sc_arpcom;


	/* Headers preceeding packets placed in the transmitting
	 * or receiving queue */
	bus_dma_tag_t 			sc_hdr_dmat;
	bus_dmamap_t 			sc_hdr_dmamap;
	bus_dma_segment_t 		sc_hdr_segs[1];
	struct virtio_net_hdr 	*sc_hdrs;
#define sc_rx_hdrs	sc_hdrs
	struct virtio_net_hdr 	*sc_tx_hdrs;

	/* Control virtqueue commands */
	struct virtio_net_ctrl_cmd 	*sc_ctrl_cmd;
	bus_dmamap_t 				sc_ctrl_cmd_dmamap;
	int						   	sc_ctrl_cmd_nseg;
	bus_dma_segment_t 			*sc_ctrl_cmd_segment;

	struct virtio_net_ctrl_status	*sc_ctrl_status;
	bus_dmamap_t 					sc_ctrl_status_dmamap;
	int 							sc_ctrl_status_nseg;
	bus_dma_segment_t 				*sc_ctrl_status_segment;

	struct virtio_net_ctrl_rx 	*sc_ctrl_rx;
	bus_dmamap_t 				sc_ctrl_rx_dmamap;
	int 						sc_ctrl_rx_nseg;
	bus_dma_segment_t 			*sc_ctrl_rx_segment;


	/* MAC address filtering */
	/* Unicast */
	struct virtio_net_ctrl_mac_tbl	*sc_ctrl_mac_tbl_uc;
	bus_dmamap_t 					sc_ctrl_tbl_uc_dmamap;
	int 							sc_ctrl_uc_nseg;
	bus_dma_segment_t 				*sc_ctrl_uc_segment;

	/* Multicast */
	struct virtio_net_ctrl_mac_tbl 	*sc_ctrl_mac_tbl_mc;
	bus_dmamap_t 					sc_ctrl_tbl_mc_dmamap;
	int 							sc_ctrl_mc_nseg;
	bus_dma_segment_t 				*sc_ctrl_mc_segment;

	int sc_ctrl_nseg_temp; /* temp */
	bus_dma_segment_t *sc_ctrl_segment_temp; /* temp */


	/* Reception header */
	bus_dmamap_t		*sc_arrays;
#define sc_rxhdr_dmamaps sc_arrays
	int 				*sc_rxhdr_nseg;
	int 				sc_nseg_temp_rx; /* temp */
	bus_dma_segment_t 	**sc_rxhdr_segment;
	bus_dma_segment_t 	*sc_segment_temp_rx; /* temp */

	/* Reception */
	bus_dmamap_t		*sc_rx_dmamaps;
	int 				*sc_rx_nseg;
	bus_dma_segment_t	**sc_rx_segment;
	struct mbuf			**sc_rx_mbufs;



	/* Transmission header */
	bus_dmamap_t 		*sc_txhdr_dmamaps;
	int 				*sc_txhdr_nseg;
	int 				sc_nseg_temp_tx; /* temp */
	bus_dma_segment_t 	**sc_txhdr_segment;
	bus_dma_segment_t 	*sc_segment_temp_tx; /* temp */

	/* Transmission */
	bus_dmamap_t 		*sc_tx_dmamaps;
	int 				*sc_tx_nseg;
	bus_dma_segment_t 	**sc_tx_segment;
	struct mbuf			**sc_tx_mbufs;

	volatile enum  {
		ISFREE, INUSE, DONE
	} sc_ctrl_inuse;

	volatile enum  {
		SLEEP, AWAKE
	} sc_run;

	struct cv 				sc_ctrl_wait;
	struct lock 			sc_ctrl_wait_lock;
	struct lwkt_serialize 	sc_serializer;
	struct spinlock			lock_io;


	/* LWKT messages*/
	struct lwkt_msg		sc_lmsg;
	struct lwkt_port 	sc_port;
	struct lock 		sc_lock;
	struct thread 		*sc_rx_td;
	struct thread		*sc_promisc_td;
	int 				sc_init; /* deferred_init job is done*/
	lwkt_msg 			sc_msg;

	struct thread 		*sc_ctrl_done;
	struct lock			sc_done;
	int 				sc_ident;

	struct spinlock		mtx;

};


#endif
