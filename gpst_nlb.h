/*
 * GlobalProtect NLB tunnel-control wire helpers
 *
 * PanGPS accepts a tunnel response when the datagram is at least 17 bytes
 * and either its first word is zero or bytes 4..7 contain "CTPG".
 */

#ifndef OPENCONNECT_GPST_NLB_H
#define OPENCONNECT_GPST_NLB_H

#define GP_NLB_CONTROL_HEADER_LEN 17

static inline int gp_nlb_is_tunnel_response(const unsigned char *buf, int len)
{
	if (!buf || len < GP_NLB_CONTROL_HEADER_LEN)
		return 0;
	if (!(buf[0] | buf[1] | buf[2] | buf[3]))
		return 1;
	return buf[4] == 'C' && buf[5] == 'T' &&
		buf[6] == 'P' && buf[7] == 'G';
}

#endif /* OPENCONNECT_GPST_NLB_H */
