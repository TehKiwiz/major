#ifndef CHANNELSET_H
#define CHANNELSET_H

#include <stdint.h>

#define CHANNEL_MAX 255
typedef uint32_t channelset_t[8];

static inline void channel_zero(channelset_t *cs) {
	uint32_t *c = (uint32_t*)cs;
	c[0] = c[1] = c[2] = c[3] = 0;
	c[4] = c[5] = c[6] = c[7] = 0;
}

static inline void channel_set(channelset_t *cs, uint8_t chan) {
	uint32_t *c = (uint32_t*)cs;
	c[chan/32] |= 1 << (chan % 32);
}

static inline void channel_unset(channelset_t *cs, uint8_t chan) {
	uint32_t *c = (uint32_t*)cs;
	c[chan/32] &= ~(1 << (chan % 32));
}

static inline int channel_isset(channelset_t *cs, uint8_t chan) {
	uint32_t *c = (uint32_t*)cs;
	return !!(c[chan/32] & (1 << (chan % 32)));
}

static inline void channel_copy(channelset_t *dest, channelset_t *src) {
	uint32_t i, *dc, *sc;
	dc = (uint32_t*)dest;
	sc = (uint32_t*)src;
	for (i=0; i<8; i++)
		dc[i] = sc[i];
}

#endif
