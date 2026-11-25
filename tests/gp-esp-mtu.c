/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <config.h>

#include "openconnect-internal.h"

#include <stdio.h>
#include <stdlib.h>

static int wire_size(struct openconnect_info *vpninfo, int inner_mtu)
{
	struct pkt *pkt = calloc(1, sizeof(*pkt) + inner_mtu + vpninfo->pkt_trailer);
	int len;

	if (!pkt)
		return -1;
	pkt->len = inner_mtu;
	len = construct_esp_packet(vpninfo, pkt, IPPROTO_IPIP);
	free(pkt);
	return len < 0 ? len : 20 /* IPv4 */ + 8 /* UDP */ + len;
}

int main(void)
{
	const int path_mtu = 1500;
	const struct vpn_proto proto = { .proto = PROTO_GPST };
	struct sockaddr peer = { .sa_family = AF_INET };
	struct openconnect_info vpninfo = {
		.proto = &proto,
		.peer_addr = &peer,
		.dtls_addr = &peer,
		.basemtu = path_mtu,
		.ssl_fd = -1,
		.verbose = -1,
		.esp_enc = ENC_AES_128_GCM,
		.esp_hmac = HMAC_NONE,
		.enc_key_len = 16 + ESP_GCM_SALT_LEN,
		.esp_gcm_icv = 16,
	};
	int mtu, full_size, next_size;

	if (openconnect_init_ssl() || openconnect_setup_esp_keys(&vpninfo, 0)) {
		fprintf(stderr, "Failed to initialize ESP keys\n");
		return 1;
	}

	mtu = esp_calculate_mtu(&vpninfo);
	full_size = wire_size(&vpninfo, mtu);
	next_size = wire_size(&vpninfo, mtu + 1);
	esp_shutdown(&vpninfo);

	if (full_size < 0 || full_size > path_mtu || next_size <= path_mtu) {
		fprintf(stderr, "MTU %d encodes to %d bytes and MTU+1 to %d bytes on a %d-byte path\n",
			mtu, full_size, next_size, path_mtu);
		return 1;
	}
	return 0;
}
