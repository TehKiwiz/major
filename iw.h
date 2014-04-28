#ifndef IW_H
#define IW_H

#include <stdint.h>
#include <sys/socket.h>
#include <linux/wireless.h>


struct radiotap_hdr {
	uint8_t  version;
	uint8_t  pad;
	uint16_t len;
	uint32_t present;
} __attribute__((__packed__));

struct write_radiotap_data {
	uint8_t  rate;
	uint8_t  pad;
	uint16_t tx_flags;
} __attribute__((__packed__));

#define RADIOTAP_F_PRESENT_RATE	(1<<2)
#define RADIOTAP_F_PRESENT_TX_FLAGS	(1<<15)
#define RADIOTAP_F_TX_FLAGS_NOACK	0x0008
#define RADIOTAP_F_TX_FLAGS_NOSEQ	0x0010

struct iw_dev {
	char ifname[IFNAMSIZ+1];
	int ifindex;
	int fd_in;
	int fd_out;
	volatile int chan;
	struct ifreq old_flags;
	struct iwreq old_mode;
};


void iw_init_dev(struct iw_dev *dev);
int iw_open(struct iw_dev *dev);
void iw_close(struct iw_dev *dev);
ssize_t iw_write(struct iw_dev *dev, void *buf, size_t count);
ssize_t iw_read(struct iw_dev *dev, void *buf, size_t count, uint8_t **pkt, size_t *pkt_sz);
int iw_set_channel(struct iw_dev *dev, int chan);

#endif
