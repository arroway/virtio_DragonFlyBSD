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

#include <bus/pci/pcivar.h>
#include <bus/pci/pcireg.h>
#include <sys/mutex2.h>
#include <sys/thread2.h>
#include <sys/taskqueue.h>
#define NBPG 4096 //bytes per page

/* Virtio product id (subsystem) */
#define PCI_PRODUCT_VIRTIO_NETWORK	1
#define PCI_PRODUCT_VIRTIO_BLOCK	2
#define PCI_PRODUCT_VIRTIO_CONSOLE	3
#define PCI_PRODUCT_VIRTIO_ENTROPY	4
#define PCI_PRODUCT_VIRTIO_BALLOON	5
#define PCI_PRODUCT_VIRTIO_9P		9

/* Virtio header */
#define VIRTIO_CONFIG_DEVICE_FEATURES	0 /* 32bit */
#define VIRTIO_CONFIG_GUEST_FEATURES	4 /* 32bit */
#define  VIRTIO_F_NOTIFY_ON_EMPTY		(1<<24)
#define  VIRTIO_F_RING_INDIRECT_DESC		(1<<28)
#define  VIRTIO_F_BAD_FEATURE			(1<<30)
#define VIRTIO_CONFIG_QUEUE_ADDRESS	8 /* 32bit */
#define VIRTIO_CONFIG_QUEUE_SIZE	12 /* 16bit */
#define VIRTIO_CONFIG_QUEUE_SELECT	14 /* 16bit */
#define VIRTIO_CONFIG_QUEUE_NOTIFY	16 /* 16bit */
#define VIRTIO_CONFIG_DEVICE_STATUS	18 /* 8bit */
#define  VIRTIO_CONFIG_DEVICE_STATUS_RESET	0
#define  VIRTIO_CONFIG_DEVICE_STATUS_ACK	1
#define  VIRTIO_CONFIG_DEVICE_STATUS_DRIVER	2
#define  VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK	4
#define  VIRTIO_CONFIG_DEVICE_STATUS_FAILED	128
#define VIRTIO_CONFIG_ISR_STATUS	19 /* 8bit */
#define  VIRTIO_CONFIG_ISR_CONFIG_CHANGE	2
#define VIRTIO_CONFIG_CONFIG_VECTOR	20 /* 16bit, optional */
#define VIRTIO_CONFIG_DEVICE_CONFIG_NOMSI	20
#define VIRTIO_CONFIG_DEVICE_CONFIG_MSI		22
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
	
/* Virtqueue */
/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT       1
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE      2
/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT	4

/* The Host uses this in used->flags to advise the Guest: don't kick me
 * when you add a buffer.  It's unreliable, so it's simply an
 * optimization.  Guest will still kick if it's out of buffers. */
#define VRING_USED_F_NO_NOTIFY  1
/* The Guest uses this in avail->flags to advise the Host: don't
 * interrupt me when you consume a buffer.  It's unreliable, so it's
 * simply an optimization.  */
#define VRING_AVAIL_F_NO_INTERRUPT      1
/* Virtio ring descriptors: 16 bytes.
 * These can chain together via "next". */
struct vring_desc {
        /* Address (guest-physical). */
        uint64_t addr;
        /* Length. */
        uint32_t len;
        /* The flags as indicated above. */
        uint16_t flags;
        /* We chain unused descriptors via this, too */
        uint16_t next;
} __packed;

struct vring_avail {
        uint16_t flags;
        uint16_t idx;
        uint16_t ring[0];
} __packed;

/* u32 is used here for ids for padding reasons. */
struct vring_used_elem {
        /* Index of start of used descriptor chain. */
        uint32_t id;
        /* Total length of the descriptor chain which was written to. */
        uint32_t len;
} __packed;

struct vring_used {
        uint16_t flags;
        uint16_t idx;
        struct vring_used_elem ring[0];
} __packed;
struct vq_entry {
	TAILQ_ENTRY(vq_entry)	qe_list; /* free list */
	uint16_t		qe_index; /* index in vq_desc array */
	/* followings are used only when it is the `head' entry */
	int16_t			qe_next;     /* next enq slot */
	bool			qe_indirect; /* 1 if using indirect */
	struct vring_desc	*qe_desc_base;
};
#define VIRTIO_PAGE_SIZE	(4096)
struct virtqueue {
	struct virtio_blk_softc *vq_owner;
	bus_dma_tag_t       vq_dmat;
	bus_dmamap_t        vq_dmamap;
	bus_addr_t      bus_addr;
	unsigned int        vq_num;	/* queue size (# of entries) */
	int         vq_index; /* queue number (0, 1, ...) */

	/* virtqueue allocation info */
	void            *vq_vaddr;
	int         vq_availoffset;
	int         vq_usedoffset;
	int         vq_indirectoffset;
	int         vq_maxsegsize;
	int         vq_maxnsegs;/* vring pointers (KVA) */
    void            *vq_indirect;
	unsigned int        vq_bytesize;

    /* vring pointers (KVA) */
    struct vring_desc   *vq_desc;
	struct vring_avail  *vq_avail;
	struct vring_used   *vq_used;

    /* free entry management */
    struct vq_entry     *vq_entries; /* free entry management */
    TAILQ_HEAD(, vq_entry) vq_freelist;
    struct spinlock		vq_freelist_lock;

    /* enqueue/dequeue status */
    uint16_t		vq_avail_idx;
	uint16_t		vq_used_idx;
    int			vq_queued;
    struct spinlock		vq_aring_lock;
	struct spinlock		vq_uring_lock;

    /* interrupt handler */
	int			(*vq_done)(struct virtqueue*);
};
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
	uint8_t				vr_status;
	struct buf			*vr_bp;

    bus_dmamap_t			cmd_dmap;
    bus_addr_t	ds_addr;	/* DMA address */
	bus_size_t	ds_len;		/* length of transfer */

	bus_dmamap_t			payload_dmap;
    bus_dma_segment_t *segs;
    int nseg;
};

struct virtio_blk_softc {
	device_t dev;

	bus_space_tag_t     sc_iot;
	bus_space_handle_t  sc_ioh;
	int         sc_config_offset;
    

	bool sc_indirect;
	int rid_irq; 
	int sc_readonly; 
	struct resource *res_irq;
	bus_dma_tag_t       virtio_dmat;
	uint32_t    sc_features;
	int     maxxfersize;
	/* vring pointers (KVA) */
	struct vring_desc   *vq_desc;
	struct vring_avail  *vq_avail;
	struct vring_used   *vq_used;
	void            *vq_indirect;

    struct virtqueue sc_vq;

    /*Block stuff*/	
    cdev_t 			cdev;
    struct devstat			stats;
    struct disk disk;

    bus_dma_tag_t requests_dmat;
	bus_dmamap_t cmds_dmamap;

    bus_dma_tag_t payloads_dmat;
	//bus_dma_tag_t payloads_dmat;
	//bus_dmamap_t payloads_dmamap;

   	struct virtio_blk_req	*sc_reqs;
	void * virtio_intr;

    int         (*sc_config_change)(struct virtio_blk_softc*);
	/* set by child */
	int         (*sc_intrhand)(struct virtio_blk_softc*);
	/* set by child */

};
