
#ifndef WIFICURSE_H
#define WIFICURSE_H

#include <stdint.h>
#include <linux/if.h>
#include "iw.h"
#include "ap_list.h"


#define VERSION	" by Ankur & Edriss ]"

struct frame_control {
	uint8_t protocol_version:2;
	uint8_t type:2;
	uint8_t subtype:4;
	uint8_t to_ds:1;
	uint8_t from_ds:1;
	uint8_t more_frag:1;
	uint8_t retry:1;
	uint8_t pwr_mgt:1;
	uint8_t more_data:1;
	uint8_t protected_frame:1;
	uint8_t order:1;
} __attribute__((__packed__));

#define FRAME_CONTROL_TYPE_MGMT_FRAME	0
#define FRAME_CONTROL_SUBTYPE_DEAUTH	12
#define FRAME_CONTROL_SUBTYPE_BEACON	8

struct sequence_control {
	uint16_t fragment:4;
	uint16_t sequence:12;
} __attribute__((__packed__));

struct mgmt_frame {
	struct frame_control fc;
	uint16_t duration;
	uint8_t  dest_mac[IFHWADDRLEN];
	uint8_t  src_mac[IFHWADDRLEN];
	uint8_t  bssid[IFHWADDRLEN];
	struct sequence_control sc;
	uint8_t  frame_body[];
} __attribute__((__packed__));

struct info_element {
	uint8_t id;
	uint8_t len;
	uint8_t info[];
} __attribute__((__packed__));

#define INFO_ELEMENT_ID_SSID	0
#define INFO_ELEMENT_ID_DS	3

struct beacon_frame_body {
	uint64_t timestamp;
	uint16_t interval;
	uint16_t capabilities;
	uint8_t  infos[];
} __attribute__((__packed__));


int send_deauth(struct iw_dev *dev, struct access_point *ap);
int read_ap_info(struct iw_dev *dev, struct ap_info *api);

#endif
