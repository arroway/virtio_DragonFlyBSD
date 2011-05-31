virtio* at pci? dev ? function ?
viomb* at virtio?
ld* at virtio?
vioif* at virtio?

Tested with 5.0.2/i386 on qemu-kvm-0.12 (noacpi) and 0.11.
            5.99.29/amd64 on VirtualBox-OSE 3.2.0.
	    (small modification neeeded in if_vioif.c around bpf)
TODO: vioif offloading (TSO and CSUM_(TC|UD)Pv[46]_Tx only??)
      cleanup
      detach
