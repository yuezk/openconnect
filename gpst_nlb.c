/*
 * GlobalProtect NLB (Network Load Balancer) tunnel support
 *
 * Reverse-engineering notes from PanGPS 6.3.3.1 (GlobalProtect_UI_deb-6.3.3.1-619):
 *
 * Detection (ClientConfig.cpp):
 *   - NLB gateways return <hs-key>, <enc-hs-key>, <tunnel-opaque>, <valid-period>
 *   - Non-NLB logs: "hs-key section is not specified. Non-nlb"
 *
 * Config field usage:
 *   hs-key        Handshake key (<bits> + <val> hex); fed to pan_esp_encap
 *   enc-hs-key    Base64 encrypted auxiliary key; likely decrypts tunnel-opaque
 *   tunnel-opaque Base64 blob stored internally as opaqueBlob
 *   valid-period  Seconds until tunnel-opaque must be refreshed via getconfig.esp
 *   gw-address    ESP magic / VIP; NLB gateways use 127.127.127.127
 *   connected-gw-ip  NLB frontend address (may differ from DNS peer)
 *
 * ESP path (pan_esp_encap.cpp, PanNATTunnelVPN.cpp):
 *   - Standard ESP keys from <ipsec> XML are installed via pan_esp_encap_init
 *   - Outbound UDP payloads wrapped by EncapSendData using opaqueBlob + pan_hmac
 *   - Inbound unwrapped by DecapRecvData; failures log:
 *       "invalid tunnel packet len %u magic 0x%x type %u"
 *   - ESP probes use 56-byte ICMP payload (not openconnect's 16-byte minimum):
 *       "monitor\\0\\0pan ha 0123456789:;<=>? !\"#$%&'()*+,-./" + 0x10..0x17
 *   - Probes target tunnel VIP (<gw-address>), UDP still sent to public peer_addr
 *   - NLB keepalive sent before data: "Send keepalive first for NLB tunnel restoration"
 *
 * NLB UDP envelope (PanGPS 6.3.3.1 RE, outside ESP ciphertext):
 *   0-3   u32 magic 0x1a2b3c4d (same as GPST SSL tunnel header)
 *   4-5   u16 wire sequence (pan_hmac counter)
 *   6-7   u16 inner_len BE (= wire_len - 16)
 *   8     u8 type: 0=keepalive, 1=data
 *   9     u8 flag
 *  10-15  HMAC-SHA1(hs-key, header prefix [+ ESP]) truncated to 6 bytes
 *  16+    inner payload (ESP ciphertext for type 1)
 *
 * SSL failover path (PanSslVpn.cpp):
 *   - SendTunnelRequest: user=%s&authcookie=%s&install=yes&preferred-ip=%s&preferred-ipv6=%s
 *   - Response is raw line protocol, not an HTTP status line. NLB format (issue #526):
 *       "110 <vip><inner_gw_ip> <40-hex-sha1> START_TUNNEL"
 *     Example: "110 127.127.127.127192.168.255.43 c057fc7f... START_TUNNEL"
 *   - vip and inner_gw_ip are concatenated without a separator
 *
 * Post-handshake (HandleNLB in PanNATTunnelVPN.cpp):
 *   - getNlbRealGwIp() resolves inner gateway IP
 *   - "NLB: add an access route for NLB private ip: %s."
 *
 * NLB blob layout (PanGPS 6.3.3.1 RE, shared by enc-hs-key and tunnel-opaque):
 *   0-15   header prefix (stored; first 16 bytes of enc-hs-key blob)
 *  16-23   version marker (e.g. e5ac060000000000)
 *  24-27   tunnel session id (cleartext, matches across blobs from same session)
 *  28+     encrypted payload (enc-hs-key: 36 bytes; tunnel-opaque: 508 bytes)
 *
 * PanGPS do_ssl_decrypt / decrypt_data (6.3.3.1 RE):
 *   - TLS 1.2 "key expansion" yields server write key + IV
 *   - EVP AES-CBC decrypt on ciphertext after the 28-byte cleartext prefix
 *   - enc-hs-key yields the hs-key material; tunnel-opaque uses that key with
 *     the same TLS server write IV
 */

#include <config.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "openconnect-internal.h"

#define GP_NLB_HDR_LEN		16
#define GP_NLB_MAGIC		0x1a2b3c4d
#define GP_NLB_TYPE_KEEPALIVE	0
#define GP_NLB_TYPE_DATA	1

/* Official 56-byte ESP probe payload (PanGPS / Windows client) */
static const unsigned char gp_nlb_probe_template[56] =
	"monitor\x00\x00pan ha 0123456789:;<=>? !\"#$%&'()*+,-./"
	"\x10\x11\x12\x13\x14\x15\x16\x17";

#define GP_NLB_SSL_PROTO_VERSION 110
#define GP_NLB_OPAQUE_REFRESH_MARGIN 60
#define GP_NLB_BLOB_HDR_LEN		24
#define GP_NLB_BLOB_SESSION_OFF		24
#define GP_NLB_BLOB_CIPHER_OFF		28
#define GP_NLB_ENC_HS_KEY_CIPHER_LEN	36
#define GP_NLB_HDR_AUTH_LEN		6
#define GP_NLB_HDR_SIGN_LEN		10

static int gp_nlb_is_ipv4(const char *s)
{
	struct in_addr a;
	return s && inet_pton(AF_INET, s, &a) == 1;
}

static int gp_nlb_split_concat_ips(const char *concat, const char *hint_vip,
				     char **vip, char **inner)
{
	const char *split;
	size_t vip_len;

	if (!concat || !*concat)
		return -EINVAL;

	if (hint_vip && !strncmp(concat, hint_vip, strlen(hint_vip))) {
		vip_len = strlen(hint_vip);
		if (concat[vip_len] && gp_nlb_is_ipv4(concat + vip_len)) {
			STRDUP(*vip, hint_vip);
			STRDUP(*inner, concat + vip_len);
			return 0;
		}
	}

	for (split = concat; *split; split++) {
		if (*split != '.' && !isdigit((unsigned char)*split))
			continue;
		if (!gp_nlb_is_ipv4(concat) || !gp_nlb_is_ipv4(split))
			continue;
		vip_len = split - concat;
		if (!vip_len)
			continue;
		*vip = strndup(concat, vip_len);
		*inner = strdup(split);
		if (!*vip || !*inner) {
			free(*vip);
			free(*inner);
			*vip = *inner = NULL;
			return -ENOMEM;
		}
		return 0;
	}

	return -EINVAL;
}

static void gp_nlb_clear_opaque_blob(struct gp_nlb_config *nlb)
{
	nlb->opaque_body_ready = 0;
	memset(nlb->opaque_key, 0, sizeof(nlb->opaque_key));
	nlb->opaque_key_len = 0;
	if (nlb->opaque_blob) {
		memset(nlb->opaque_blob, 0, nlb->opaque_blob_len);
		free(nlb->opaque_blob);
		nlb->opaque_blob = NULL;
	}
	nlb->opaque_blob_len = 0;
	nlb->blob_session_id = 0;
}

static int gp_nlb_parse_blob_header(struct openconnect_info *vpninfo,
				    const unsigned char *blob, int len,
				    struct gp_nlb_config *nlb)
{
	if (!blob || len < GP_NLB_BLOB_HDR_LEN)
		return -EINVAL;

	nlb->blob_session_id = load_be32(blob + GP_NLB_BLOB_SESSION_OFF);
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("NLB blob session id 0x%08x, version marker %02x%02x%02x%02x\n"),
		     nlb->blob_session_id,
		     blob[16], blob[17], blob[18], blob[19]);
	return 0;
}

static int gp_nlb_decrypt_enc_hs_key(struct openconnect_info *vpninfo,
				     struct gp_nlb_config *nlb,
				     const unsigned char *blob, int len)
{
	unsigned char plain[64];
	int plain_len = sizeof(plain);
	int ret;

	if (!nlb->enc_hs_key)
		return 0;
	if (len < GP_NLB_BLOB_CIPHER_OFF + GP_NLB_ENC_HS_KEY_CIPHER_LEN)
		return -EINVAL;

	ret = gp_ssl_decrypt_blob(vpninfo,
				  blob + GP_NLB_BLOB_CIPHER_OFF,
				  GP_NLB_ENC_HS_KEY_CIPHER_LEN,
				  plain, &plain_len);
	if (ret < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("enc-hs-key TLS decipherment failed\n"));
		return -EINVAL;
	}

	if (plain_len <= 0 || plain_len > (int)sizeof(nlb->opaque_key))
		return -EINVAL;

	memcpy(nlb->opaque_key, plain, plain_len);
	nlb->opaque_key_len = plain_len;
	memset(plain, 0, sizeof(plain));
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Decrypted enc-hs-key (%d bytes)\n"), plain_len);
	return 0;
}

static int gp_nlb_decrypt_opaque_body(struct openconnect_info *vpninfo,
				      struct gp_nlb_config *nlb)
{
	const unsigned char *payload;
	int payload_len, out_len;
	unsigned char *out;

	if (!nlb->opaque_blob || nlb->opaque_blob_len <= GP_NLB_BLOB_CIPHER_OFF)
		return 0;
	if (!nlb->opaque_key_len)
		return -EINVAL;

	payload = nlb->opaque_blob + GP_NLB_BLOB_CIPHER_OFF;
	payload_len = nlb->opaque_blob_len - GP_NLB_BLOB_CIPHER_OFF;
	out = malloc(payload_len);
	if (!out)
		return -ENOMEM;
	out_len = payload_len;

	if (gp_ssl_decrypt_blob_key(vpninfo, nlb->opaque_key, nlb->opaque_key_len,
				    NULL, 0, payload, payload_len, out, &out_len) < 0) {
		free(out);
		vpn_progress(vpninfo, PRG_ERR,
			     _("tunnel-opaque body decipherment failed\n"));
		return -EINVAL;
	}

	memset(out, 0, out_len);
	free(out);
	nlb->opaque_body_ready = 1;
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Decrypted tunnel-opaque body (%d bytes)\n"), out_len);
	return 0;
}

static void gp_nlb_write_hdr(unsigned char *hdr, struct gp_nlb_config *nlb,
			     uint16_t inner_len, uint8_t type)
{
	store_be32(hdr, GP_NLB_MAGIC);
	store_be16(hdr + 4, nlb->wire_seq++);
	store_be16(hdr + 6, inner_len);
	hdr[8] = type;
	hdr[9] = 0;
	memset(hdr + 10, 0, GP_NLB_HDR_AUTH_LEN);
}

static int gp_nlb_sign_hdr(struct openconnect_info *vpninfo,
			   struct gp_nlb_config *nlb,
			   unsigned char *hdr,
			   const unsigned char *esp, int esplen)
{
	unsigned char mac[SHA1_SIZE];

	if (!nlb->hs_key_len)
		return -EINVAL;

	if (gp_nlb_hmac_sha1(nlb->hs_key, nlb->hs_key_len,
			     hdr, GP_NLB_HDR_SIGN_LEN,
			     esp, esplen, mac) < 0)
		return -EINVAL;
	memcpy(hdr + GP_NLB_HDR_SIGN_LEN, mac, GP_NLB_HDR_AUTH_LEN);
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("NLB sign: seq=%u type=%u inner_len=%u esplen=%d\n"),
		     load_be16(hdr + 4), hdr[8], load_be16(hdr + 6), esplen);
	dump_buf_hex(vpninfo, PRG_DEBUG, '>', hdr, GP_NLB_HDR_LEN);
	return 0;
}

static int gp_nlb_verify_hdr(struct openconnect_info *vpninfo,
			     struct gp_nlb_config *nlb,
			     const unsigned char *hdr,
			     const unsigned char *esp, int esplen)
{
	unsigned char mac[SHA1_SIZE];
	const unsigned char *expect;

	if (!nlb->hs_key_len)
		return -EINVAL;

	if (gp_nlb_hmac_sha1(nlb->hs_key, nlb->hs_key_len,
			     hdr, GP_NLB_HDR_SIGN_LEN,
			     esp, esplen, mac) < 0)
		return -EINVAL;

	expect = hdr + GP_NLB_HDR_SIGN_LEN;
	if (memcmp(expect, mac, GP_NLB_HDR_AUTH_LEN)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("NLB envelope HMAC mismatch: seq=%u type=%u inner_len=%u esplen=%d\n"),
			     load_be16(hdr + 4), hdr[8], load_be16(hdr + 6), esplen);
		dump_buf_hex(vpninfo, PRG_DEBUG, '<', (unsigned char *)expect,
			     GP_NLB_HDR_AUTH_LEN);
		dump_buf_hex(vpninfo, PRG_DEBUG, '=', mac, GP_NLB_HDR_AUTH_LEN);
		dump_buf_hex(vpninfo, PRG_DEBUG, '>', (unsigned char *)hdr,
			     GP_NLB_HDR_LEN);
		return -EINVAL;
	}
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("NLB verify ok: seq=%u type=%u inner_len=%u esplen=%d\n"),
		     load_be16(hdr + 4), hdr[8], load_be16(hdr + 6), esplen);
	return 0;
}

int gpst_nlb_pkt_slack(struct openconnect_info *vpninfo)
{
	return vpninfo->gp_nlb.enabled ? GP_NLB_HDR_LEN : 0;
}

int gpst_nlb_prepare(struct openconnect_info *vpninfo)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;
	struct in_addr vip;
	int len, ret;

	if (!nlb->enabled)
		return 0;

	nlb->keepalive_sent = 0;
	nlb->wire_seq = 0;

	if (nlb->tunnel_vip && inet_pton(AF_INET, nlb->tunnel_vip, &vip) == 1) {
		vpninfo->esp_magic_af = AF_INET;
		memcpy(vpninfo->esp_magic, &vip, sizeof(vip));
	} else if (!nlb->tunnel_vip && nlb->tunnel_opaque) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("NLB enabled but no tunnel VIP yet; expecting 127.127.127.127 from <gw-address>\n"));
	}

	gp_nlb_clear_opaque_blob(nlb);

	if (nlb->enc_hs_key) {
		unsigned char *enc_blob = openconnect_base64_decode(&len, nlb->enc_hs_key);

		if (!enc_blob || len <= 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to base64-decode enc-hs-key\n"));
			free(enc_blob);
			return -EINVAL;
		}
		gp_nlb_parse_blob_header(vpninfo, enc_blob, len, nlb);
		ret = gp_nlb_decrypt_enc_hs_key(vpninfo, nlb, enc_blob, len);
		memset(enc_blob, 0, len);
		free(enc_blob);
		if (ret < 0)
			return ret;
	}

	if (nlb->tunnel_opaque) {
		nlb->opaque_blob = openconnect_base64_decode(&len, nlb->tunnel_opaque);
		if (!nlb->opaque_blob || len <= 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to base64-decode tunnel-opaque\n"));
			free(nlb->opaque_blob);
			nlb->opaque_blob = NULL;
			return -EINVAL;
		}
		nlb->opaque_blob_len = len;
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Decoded tunnel-opaque (%d bytes)\n"), len);
		if (!nlb->blob_session_id)
			gp_nlb_parse_blob_header(vpninfo, nlb->opaque_blob, len, nlb);
		ret = gp_nlb_decrypt_opaque_body(vpninfo, nlb);
		if (ret < 0)
			return ret;
	}

	if (!nlb->hs_key_len) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("NLB requires hs-key for envelope authentication\n"));
		return -EINVAL;
	}
	if (nlb->tunnel_opaque && !nlb->opaque_body_ready) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("NLB tunnel-opaque present but decipherment failed\n"));
		return -EINVAL;
	}

	vpn_progress(vpninfo, PRG_INFO,
		     _("NLB crypto ready: hs_key=%d bytes opaque_key=%d bytes opaque_body=%s\n"),
		     nlb->hs_key_len, nlb->opaque_key_len,
		     nlb->opaque_body_ready ? "ready" : "none");
	return 0;
}

const unsigned char *gpst_nlb_probe_payload(size_t *len)
{
	if (len)
		*len = sizeof(gp_nlb_probe_template);
	return gp_nlb_probe_template;
}

int gpst_nlb_send_esp_keepalive(struct openconnect_info *vpninfo)
{
	unsigned char hdr[GP_NLB_HDR_LEN];

	if (!vpninfo->gp_nlb.enabled || vpninfo->dtls_fd < 0)
		return 0;

	gp_nlb_write_hdr(hdr, &vpninfo->gp_nlb, 0, GP_NLB_TYPE_KEEPALIVE);
	if (gp_nlb_sign_hdr(vpninfo, &vpninfo->gp_nlb, hdr, NULL, 0) < 0)
		return -EINVAL;
	vpn_progress(vpninfo, PRG_DEBUG, _("Send NLB ESP keepalive\n"));
	if (send(vpninfo->dtls_fd, hdr, sizeof(hdr), 0) < 0) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Failed to send NLB ESP keepalive: %s\n"),
			     strerror(errno));
		return -errno;
	}
	return 0;
}

int gpst_nlb_esp_encap(struct openconnect_info *vpninfo, struct pkt *pkt, int *len)
{
	int esplen;
	unsigned char *wire;

	if (!vpninfo->gp_nlb.enabled)
		return 0;

	esplen = *len;
	wire = (unsigned char *)&pkt->esp;

	if (esplen <= 0)
		return -EINVAL;

	if ((char *)wire + esplen + GP_NLB_HDR_LEN >
	    (char *)pkt + sizeof(*pkt) + pkt->alloc_len)
		return -ENOSPC;

	memmove(wire + GP_NLB_HDR_LEN, wire, esplen);
	gp_nlb_write_hdr(wire, &vpninfo->gp_nlb, esplen, GP_NLB_TYPE_DATA);
	if (gp_nlb_sign_hdr(vpninfo, &vpninfo->gp_nlb, wire,
			    wire + GP_NLB_HDR_LEN, esplen) < 0)
		return -EINVAL;
	*len = esplen + GP_NLB_HDR_LEN;
	return 0;
}

int gpst_nlb_esp_decap(struct openconnect_info *vpninfo, struct pkt *pkt, int *len)
{
	unsigned char *wire;
	uint16_t inner_len;
	uint8_t type;
	uint32_t magic;
	int wire_len;

	if (!vpninfo->gp_nlb.enabled)
		return 0;

	wire = (unsigned char *)&pkt->esp;
	wire_len = *len;

	if (wire_len < GP_NLB_HDR_LEN)
		return -EINVAL;

	magic = load_be32(wire);
	type = wire[8];
	inner_len = load_be16(wire + 6);

	if (magic != GP_NLB_MAGIC ||
	    (type != GP_NLB_TYPE_KEEPALIVE && type != GP_NLB_TYPE_DATA) ||
	    wire_len != GP_NLB_HDR_LEN + inner_len) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("invalid NLB tunnel packet: wire_len=%d inner_len=%u magic=0x%x type=%u (expected %d)\n"),
			     wire_len, inner_len, magic, type,
			     GP_NLB_HDR_LEN + inner_len);
		dump_buf_hex(vpninfo, PRG_DEBUG, '<', wire, GP_NLB_HDR_LEN);
		return -EINVAL;
	}

	if (type == GP_NLB_TYPE_KEEPALIVE) {
		if (gp_nlb_verify_hdr(vpninfo, &vpninfo->gp_nlb, wire, NULL, 0) < 0)
			return -EINVAL;
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Got NLB ESP keepalive response\n"));
		return 1;
	}

	if (gp_nlb_verify_hdr(vpninfo, &vpninfo->gp_nlb, wire,
			      wire + GP_NLB_HDR_LEN, inner_len) < 0)
		return -EINVAL;

	memmove(wire, wire + GP_NLB_HDR_LEN, inner_len);
	*len = inner_len;
	return 0;
}

int gpst_nlb_parse_ssl_response(const char *buf, int len, struct gp_nlb_config *nlb)
{
	char *line, *vip = NULL, *inner = NULL, *hash, *start, *concat;
	const char *hint_vip;
	long version;
	int ret = -EINVAL;

	if (!buf || len <= 0 || !nlb)
		return -EINVAL;

	line = strndup(buf, len);
	if (!line)
		return -ENOMEM;

	/* Trim trailing CR/LF */
	for (char *p = line + strlen(line); p > line; p--) {
		if (p[-1] == '\r' || p[-1] == '\n')
			p[-1] = '\0';
		else
			break;
	}

	if (!strncmp(line, "START_TUNNEL", 12)) {
		ret = 0;
		goto out;
	}

	start = strstr(line, " START_TUNNEL");
	if (!start) {
		ret = -EINVAL;
		goto out;
	}
	*start = '\0';
	hash = strrchr(line, ' ');
	if (!hash || strlen(hash + 1) != 40) {
		ret = -EINVAL;
		goto out;
	}
	*hash++ = '\0';

	if (sscanf(line, "%ld", &version) != 1 || version != GP_NLB_SSL_PROTO_VERSION) {
		ret = -EINVAL;
		goto out;
	}

	concat = strchr(line, ' ');
	if (!concat) {
		ret = -EINVAL;
		goto out;
	}
	concat++;

	hint_vip = nlb->tunnel_vip ?: "127.127.127.127";
	if (gp_nlb_split_concat_ips(concat, hint_vip, &vip, &inner)) {
		ret = -EINVAL;
		goto out;
	}

	free(nlb->tunnel_vip);
	free(nlb->inner_gw_ip);
	free(nlb->in_tunnel_gw_cert_chksum);
	nlb->tunnel_vip = vip;
	nlb->inner_gw_ip = inner;
	vip = inner = NULL;
	STRDUP(nlb->in_tunnel_gw_cert_chksum, hash);
	nlb->enabled = 1;
	ret = 0;

out:
	free(vip);
	free(inner);
	free(line);
	return ret;
}

static struct oc_split_include *gp_nlb_clone_split_list(struct oc_split_include *list,
							struct oc_vpn_option **opts,
							const char *optname)
{
	struct oc_split_include *head = NULL, **tail = &head;

	for (; list; list = list->next) {
		struct oc_split_include *inc = malloc(sizeof(*inc));

		if (!inc)
			return NULL;
		inc->route = add_option_dup(opts, optname, list->route, -1);
		if (!inc->route) {
			free(inc);
			return NULL;
		}
		inc->next = NULL;
		*tail = inc;
		tail = &inc->next;
	}
	return head;
}

static int gp_nlb_route_list_contains(struct oc_split_include *list, const char *ip)
{
	char route[64];

	if (snprintf(route, sizeof(route), "%s/32", ip) >= (int)sizeof(route))
		return 0;

	for (; list; list = list->next) {
		if (list->route && !strcmp(list->route, route))
			return 1;
	}
	return 0;
}

static int gpst_nlb_update_esp_magic(struct openconnect_info *vpninfo)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;
	struct in_addr vip;

	if (!nlb->tunnel_vip || inet_pton(AF_INET, nlb->tunnel_vip, &vip) != 1)
		return 0;

	vpninfo->esp_magic_af = AF_INET;
	memcpy(vpninfo->esp_magic, &vip, sizeof(vip));
	return 0;
}

int gpst_nlb_apply_routes(struct openconnect_info *vpninfo)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;
	struct oc_ip_info new_ip_info;
	struct oc_vpn_option *new_opts = NULL;
	struct oc_vpn_option *opt;
	struct oc_split_include *inc;
	char route[64];
	int ret = 0;

	if (!nlb->enabled || !nlb->inner_gw_ip)
		return 0;

	if (gp_nlb_route_list_contains(vpninfo->ip_info.split_includes, nlb->inner_gw_ip))
		return 0;

	if (snprintf(route, sizeof(route), "%s/32", nlb->inner_gw_ip) >= (int)sizeof(route))
		return -EINVAL;

	for (opt = vpninfo->cstp_options; opt; opt = opt->next) {
		if (!add_option_dup(&new_opts, opt->option, opt->value, -1)) {
			ret = -ENOMEM;
			goto err;
		}
	}

	inc = malloc(sizeof(*inc));
	if (!inc) {
		ret = -ENOMEM;
		goto err;
	}
	inc->route = add_option_dup(&new_opts, "split-include", route, -1);
	if (!inc->route) {
		free(inc);
		ret = -ENOMEM;
		goto err;
	}
	inc->next = NULL;

	new_ip_info = vpninfo->ip_info;
	new_ip_info.split_includes = gp_nlb_clone_split_list(vpninfo->ip_info.split_includes,
							     &new_opts, "split-include");
	new_ip_info.split_excludes = gp_nlb_clone_split_list(vpninfo->ip_info.split_excludes,
							     &new_opts, "split-exclude");
	if ((vpninfo->ip_info.split_includes && !new_ip_info.split_includes) ||
	    (vpninfo->ip_info.split_excludes && !new_ip_info.split_excludes)) {
		free(inc);
		ret = -ENOMEM;
		goto err;
	}

	inc->next = new_ip_info.split_includes;
	new_ip_info.split_includes = inc;
	inc = NULL;

	vpn_progress(vpninfo, PRG_INFO,
		     _("NLB: add an access route for NLB private ip: %s.\n"),
		     nlb->inner_gw_ip);

	if (install_vpn_opts(vpninfo, new_opts, &new_ip_info)) {
		free_split_routes(&new_ip_info);
		ret = -EINVAL;
		goto err;
	}
	return 0;

err:
	free_optlist(new_opts);
	free(inc);
	return ret;
}

int gpst_nlb_on_ssl_tunnel(struct openconnect_info *vpninfo)
{
	gpst_nlb_update_esp_magic(vpninfo);
	return gpst_nlb_apply_routes(vpninfo);
}

int gpst_nlb_opaque_due(struct openconnect_info *vpninfo, int *timeout)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;
	time_t now = time(NULL);
	time_t due;

	if (!nlb->enabled || !nlb->tunnel_opaque || !nlb->opaque_valid_until)
		return 0;

	due = nlb->opaque_valid_until;
	if (due > GP_NLB_OPAQUE_REFRESH_MARGIN)
		due -= GP_NLB_OPAQUE_REFRESH_MARGIN;

	return ka_check_deadline(timeout, now, due);
}

int gpst_nlb_maintenance(struct openconnect_info *vpninfo, int *timeout)
{
	if (!gpst_nlb_opaque_due(vpninfo, timeout))
		return 0;

	vpn_progress(vpninfo, PRG_INFO, _("NLB tunnel-opaque refresh due\n"));
	if (gpst_nlb_refresh_opaque(vpninfo) < 0) {
		vpn_progress(vpninfo, PRG_ERR, _("NLB tunnel-opaque refresh failed\n"));
		return -1;
	}

	vpninfo->gp_nlb.keepalive_sent = 0;
	return 1;
}

int gpst_nlb_handle_ssl_connect_response(struct openconnect_info *vpninfo,
					 const char *buf, int len)
{
	static const char start_tunnel[] = "START_TUNNEL";

	if (!buf || len <= 0)
		return -EINVAL;

	if (len >= 12 && !strncmp(buf, start_tunnel, 12))
		return gpst_nlb_on_ssl_tunnel(vpninfo);

	if (!strstr(buf, start_tunnel))
		return -EINVAL;

	if (gpst_nlb_parse_ssl_response(buf, len, &vpninfo->gp_nlb) < 0)
		return -EINVAL;

	return gpst_nlb_on_ssl_tunnel(vpninfo);
}