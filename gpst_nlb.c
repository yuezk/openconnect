/*
 * GlobalProtect NLB (Network Load Balancer) tunnel support
 *
 * PanGPS performs a separate UDP tunnel-control exchange before it sends
 * normal ESP traffic to an NLB gateway:
 *
 *   1. getconfig.esp returns hs-key, enc-hs-key, and tunnel-opaque.
 *   2. The client sends a GPTC control packet containing the two opaque
 *      values, encrypted preferred-address data, and a fixed client hash.
 *   3. The gateway returns a CTPG packet. Its type-4 field contains
 *      base64(tag[16] || iv[12] || AES-256-GCM ciphertext), encrypted with
 *      the clear hs-key from getconfig.esp.
 *   4. The decrypted XML supplies the client virtual IP and private gateway.
 *   5. ESP keepalives, probes, and data are sent directly on the UDP socket.
 *
 * NLB does not add a per-packet envelope around ESP. EncapSendData in the
 * official client calls pan_ipsec_esp_encap(), and Send writes that result
 * directly to the socket.
 */

#include <config.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "openconnect-internal.h"

#define GP_NLB_CONTROL_MAX		2048
#define GP_NLB_CONTROL_HEADER_LEN	17
#define GP_NLB_TOC_ENTRY_LEN		5
#define GP_NLB_TOC_COUNT		4
#define GP_NLB_BLOCK_ENC_HS_KEY		1
#define GP_NLB_BLOCK_TUNNEL_OPAQUE	2
#define GP_NLB_BLOCK_TUNNEL_INFO	4
#define GP_NLB_BLOCK_CLIENT_HASH	5
#define GP_NLB_GCM_TAG_LEN		16
#define GP_NLB_GCM_IV_LEN		12
#define GP_NLB_GCM_PREFIX_LEN		(GP_NLB_GCM_TAG_LEN + GP_NLB_GCM_IV_LEN)

#define GP_NLB_CONTROL_PENDING		1
#define GP_NLB_CONTROL_WAITING		2
#define GP_NLB_CONTROL_READY		3

#define GP_NLB_SSL_PROTO_VERSION	110
#define GP_NLB_OPAQUE_REFRESH_MARGIN	60

static const unsigned char gp_nlb_request_magic[4] = { 'G', 'P', 'T', 'C' };
static const unsigned char gp_nlb_response_magic[4] = { 'C', 'T', 'P', 'G' };
static const char gp_nlb_client_hash[] =
	"75cd47bf39517f376924a519c2355292a26ce63fd04eca117fb566aa0a222b41";

/* Official 56-byte ESP keepalive/probe payload. */
static const unsigned char gp_nlb_probe_template[56] __attribute__((nonstring)) =
	"monitor\x00\x00pan ha 0123456789:;<=>? !\"#$%&'()*+,-./"
	"\x10\x11\x12\x13\x14\x15\x16\x17";

struct gp_nlb_tunnel_info {
	char *vip;
	char *vip6;
	char *inner_gw;
	char *inner_gw6;
	char *dns[3];
	char *wins[3];
	int nr_dns;
	int nr_wins;
};

static int gp_nlb_is_ipv4(const char *s)
{
	struct in_addr a;

	return s && inet_pton(AF_INET, s, &a) == 1;
}

static int gp_nlb_split_concat_ips(const char *concat, const char *hint_vip,
				     char **vip, char **inner)
{
	size_t concat_len, i, vip_len;

	if (!concat || !*concat)
		return -EINVAL;
	concat_len = strlen(concat);

	if (hint_vip && !strncmp(concat, hint_vip, strlen(hint_vip))) {
		vip_len = strlen(hint_vip);
		if (concat[vip_len] && gp_nlb_is_ipv4(concat + vip_len)) {
			STRDUP(*vip, hint_vip);
			STRDUP(*inner, concat + vip_len);
			return 0;
		}
	}

	for (i = 1; i < concat_len && i <= 15; i++) {
		char candidate[16];

		if (concat_len - i > 15)
			continue;
		memcpy(candidate, concat, i);
		candidate[i] = '\0';
		if (!gp_nlb_is_ipv4(candidate) || !gp_nlb_is_ipv4(concat + i))
			continue;

		*vip = strdup(candidate);
		*inner = strdup(concat + i);
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

int gpst_nlb_prepare(struct openconnect_info *vpninfo)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;
	struct in_addr vip;

	if (!nlb->enabled)
		return 0;

	nlb->control_state = GP_NLB_CONTROL_PENDING;
	nlb->control_last_sent = 0;
	nlb->control_requests = 0;
	nlb->keepalive_sent = 0;

	if (nlb->tunnel_vip && inet_pton(AF_INET, nlb->tunnel_vip, &vip) == 1) {
		vpninfo->esp_magic_af = AF_INET;
		memcpy(vpninfo->esp_magic, &vip, sizeof(vip));
	}

	if (nlb->hs_key_len != (int)sizeof(nlb->hs_key)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("NLB requires a 256-bit hs-key for the tunnel-control exchange\n"));
		return -EINVAL;
	}
	if (!nlb->enc_hs_key || !*nlb->enc_hs_key ||
	    !nlb->tunnel_opaque || !*nlb->tunnel_opaque) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("NLB requires enc-hs-key and tunnel-opaque for the tunnel-control exchange\n"));
		return -EINVAL;
	}

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("NLB tunnel control ready: vip=%s connected_gw=%s hs_key=%d bytes enc_hs_key=%zu bytes tunnel_opaque=%zu bytes refresh=%llds\n"),
		     nlb->tunnel_vip ?: "unknown",
		     nlb->connected_gw_ip ?: "unknown",
		     nlb->hs_key_len, strlen(nlb->enc_hs_key),
		     strlen(nlb->tunnel_opaque),
		     (long long)(nlb->opaque_valid_until ?
				 nlb->opaque_valid_until - time(NULL) : 0));
	return 0;
}

const unsigned char *gpst_nlb_probe_payload(size_t *len)
{
	if (len)
		*len = sizeof(gp_nlb_probe_template);
	return gp_nlb_probe_template;
}

int gpst_nlb_control_ready(struct openconnect_info *vpninfo)
{
	return !vpninfo->gp_nlb.enabled ||
		vpninfo->gp_nlb.control_state == GP_NLB_CONTROL_READY;
}

static int gp_nlb_build_client_info(struct openconnect_info *vpninfo,
				    unsigned char **out, int *outlen)
{
	struct oc_text_buf *plain = buf_alloc();
	struct oc_text_buf *encoded = buf_alloc();
	unsigned char random_bytes[32] = { 0 };
	unsigned int random_values[8] = { 0 };
	unsigned char iv[GP_NLB_GCM_IV_LEN] = { 0 };
	unsigned char tag[GP_NLB_GCM_TAG_LEN] = { 0 };
	unsigned char *cipher = NULL, *block = NULL;
	char iv_text[128];
	int plain_len = 0, encoded_len, ret = -ENOMEM;

	*out = NULL;
	*outlen = 0;
	if (!plain || !encoded)
		goto out;

	buf_append(plain,
		   "<client-info>\t<preferred-ip>%s</preferred-ip>"
		   "\t<preferred-ipv6>%s</preferred-ipv6></client-infor>",
		   vpninfo->ip_info.addr ?: "", vpninfo->ip_info.addr6 ?: "");
	if (buf_error(plain)) {
		ret = buf_error(plain);
		goto out;
	}
	plain_len = plain->pos + 1;
	cipher = malloc(plain_len);
	if (!cipher)
		goto out;

	/* PanGPS formats eight rand() results and uses the first 12 bytes as
	 * the GCM IV. Use the same textual shape without modifying process-global
	 * PRNG state. */
	if (openconnect_random(random_bytes, sizeof(random_bytes))) {
		ret = -EIO;
		goto out;
	}
	memcpy(random_values, random_bytes, sizeof(random_values));
	if (snprintf(iv_text, sizeof(iv_text), "%u%u%u%u%u%u%u%u",
		     random_values[0] & 0x7fffffff, random_values[1] & 0x7fffffff,
		     random_values[2] & 0x7fffffff, random_values[3] & 0x7fffffff,
		     random_values[4] & 0x7fffffff, random_values[5] & 0x7fffffff,
		     random_values[6] & 0x7fffffff, random_values[7] & 0x7fffffff) <
	    GP_NLB_GCM_IV_LEN) {
		ret = -EINVAL;
		goto out;
	}
	memcpy(iv, iv_text, sizeof(iv));
	if (gp_nlb_aes256_gcm_encrypt(vpninfo->gp_nlb.hs_key, iv,
				      (unsigned char *)plain->data, plain_len,
				      cipher, tag) < 0) {
		ret = -EINVAL;
		goto out;
	}

	/* Preserve PanGPS's request wire format. It places the raw tag at offset
	 * zero, leaves bytes 16..27 clear, writes base64 ciphertext at offset 28,
	 * and reports the base64 length as the field length. */
	buf_append_base64(encoded, cipher, plain_len, 64);
	if (buf_error(encoded)) {
		ret = buf_error(encoded);
		goto out;
	}
	encoded_len = encoded->pos;
	block = calloc(1, GP_NLB_GCM_PREFIX_LEN + encoded_len);
	if (!block)
		goto out;
	memcpy(block, tag, sizeof(tag));
	memcpy(block + GP_NLB_GCM_PREFIX_LEN, encoded->data, encoded_len);
	*out = block;
	*outlen = encoded_len;
	block = NULL;
	ret = 0;

out:
	memset(random_bytes, 0, sizeof(random_bytes));
	memset(random_values, 0, sizeof(random_values));
	memset(iv, 0, sizeof(iv));
	memset(tag, 0, sizeof(tag));
	if (cipher) {
		memset(cipher, 0, plain_len);
		free(cipher);
	}
	free(block);
	buf_free(encoded);
	buf_free(plain);
	return ret;
}

static void gp_nlb_set_toc_entry(unsigned char *entry, unsigned char type,
				 uint16_t offset, uint16_t len)
{
	entry[0] = type;
	store_be16(entry + 1, offset);
	store_be16(entry + 3, len);
}

static int gp_nlb_build_tunnel_request(struct openconnect_info *vpninfo,
				       unsigned char *request, int capacity)
{
	const unsigned char *fields[GP_NLB_TOC_COUNT];
	const unsigned char types[GP_NLB_TOC_COUNT] = {
		GP_NLB_BLOCK_ENC_HS_KEY, GP_NLB_BLOCK_TUNNEL_OPAQUE,
		GP_NLB_BLOCK_TUNNEL_INFO, GP_NLB_BLOCK_CLIENT_HASH
	};
	unsigned char *client_info = NULL;
	int lengths[GP_NLB_TOC_COUNT] = { 0 };
	int payload_offset, i, ret;

	ret = gp_nlb_build_client_info(vpninfo, &client_info, &lengths[2]);
	if (ret < 0)
		return ret;
	fields[0] = (unsigned char *)vpninfo->gp_nlb.enc_hs_key;
	fields[1] = (unsigned char *)vpninfo->gp_nlb.tunnel_opaque;
	fields[2] = client_info;
	fields[3] = (unsigned char *)gp_nlb_client_hash;
	lengths[0] = strlen(vpninfo->gp_nlb.enc_hs_key);
	lengths[1] = strlen(vpninfo->gp_nlb.tunnel_opaque);
	lengths[3] = sizeof(gp_nlb_client_hash) - 1;

	payload_offset = GP_NLB_CONTROL_HEADER_LEN +
		GP_NLB_TOC_COUNT * GP_NLB_TOC_ENTRY_LEN;
	memset(request, 0, capacity);
	memcpy(request + 4, gp_nlb_request_magic, sizeof(gp_nlb_request_magic));
	request[8] = 1;
	request[9] = 1;
	store_be32(request + 12, (uint32_t)time(NULL));
	request[16] = GP_NLB_TOC_COUNT;

	for (i = 0; i < GP_NLB_TOC_COUNT; i++) {
		if (lengths[i] < 0 || lengths[i] > 0xffff ||
		    payload_offset > 0xffff || lengths[i] > capacity - payload_offset) {
			ret = -E2BIG;
			goto out;
		}
		gp_nlb_set_toc_entry(request + GP_NLB_CONTROL_HEADER_LEN +
				     i * GP_NLB_TOC_ENTRY_LEN,
				     types[i], payload_offset, lengths[i]);
		memcpy(request + payload_offset, fields[i], lengths[i]);
		payload_offset += lengths[i];
	}
	ret = payload_offset;

out:
	if (client_info) {
		memset(client_info, 0, GP_NLB_GCM_PREFIX_LEN + lengths[2]);
		free(client_info);
	}
	return ret;
}

int gpst_nlb_send_tunnel_request(struct openconnect_info *vpninfo)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;
	unsigned char request[GP_NLB_CONTROL_MAX];
	time_t now = time(NULL);
	int len, ret;

	if (!nlb->enabled || nlb->control_state == GP_NLB_CONTROL_READY)
		return 0;
	if (vpninfo->dtls_fd < 0)
		return -EINVAL;
	if (nlb->control_state == GP_NLB_CONTROL_WAITING &&
	    nlb->control_last_sent == now)
		return 0;

	len = gp_nlb_build_tunnel_request(vpninfo, request, sizeof(request));
	if (len < 0)
		return len;
	ret = send(vpninfo->dtls_fd, request, len, 0);
	if (ret != len)
		return ret < 0 ? -errno : -EIO;

	nlb->control_state = GP_NLB_CONTROL_WAITING;
	nlb->control_last_sent = now;
	nlb->control_requests++;
	time(&vpninfo->dtls_times.last_tx);
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Sent NLB tunnel-control request %u (%d bytes)\n"),
		     nlb->control_requests, len);
	return 0;
}

static int gp_nlb_replace_string(char **dst, const char *src)
{
	char *dup = strdup(src);

	if (!dup)
		return -ENOMEM;
	free(*dst);
	*dst = dup;
	return 0;
}

static int gp_nlb_is_ipv6(const char *s)
{
	struct in6_addr a;

	return s && inet_pton(AF_INET6, s, &a) == 1;
}

static void gp_nlb_free_tunnel_info(struct gp_nlb_tunnel_info *info)
{
	int i;

	free(info->vip);
	free(info->vip6);
	free(info->inner_gw);
	free(info->inner_gw6);
	for (i = 0; i < info->nr_dns; i++)
		free(info->dns[i]);
	for (i = 0; i < info->nr_wins; i++)
		free(info->wins[i]);
	memset(info, 0, sizeof(*info));
}

static int gp_nlb_parse_address_list(xmlNode *node, char **values, int *count)
{
	xmlNode *member;
	char *s = NULL;

	for (member = node->children; member && *count < 3; member = member->next) {
		if (xmlnode_get_val(member, "member", &s))
			continue;
		values[(*count)++] = s;
		s = NULL;
	}
	free(s);
	return 0;
}

static int gp_nlb_parse_tunnel_info_nodes(struct gp_nlb_tunnel_info *info,
					  xmlNode *node)
{
	char *s = NULL;
	int ret = 0;

	for (; node; node = node->next) {
		if (!xmlnode_get_val(node, "ip-address", &s)) {
			if (gp_nlb_is_ipv4(s))
				ret = gp_nlb_replace_string(&info->vip, s);
		} else if (!xmlnode_get_val(node, "ipv6-address", &s)) {
			if (gp_nlb_is_ipv6(s))
				ret = gp_nlb_replace_string(&info->vip6, s);
		} else if (!xmlnode_get_val(node, "in-tunnel-gw-ip", &s)) {
			if (gp_nlb_is_ipv4(s))
				ret = gp_nlb_replace_string(&info->inner_gw, s);
		} else if (!xmlnode_get_val(node, "in-tunnel-gw-ipv6", &s)) {
			if (gp_nlb_is_ipv6(s))
				ret = gp_nlb_replace_string(&info->inner_gw6, s);
		} else if (xmlnode_is_named(node, "dns")) {
			ret = gp_nlb_parse_address_list(node, info->dns, &info->nr_dns);
		} else if (xmlnode_is_named(node, "wins")) {
			ret = gp_nlb_parse_address_list(node, info->wins, &info->nr_wins);
		}
		free(s);
		s = NULL;
		if (ret < 0)
			return ret;
		if (node->children) {
			ret = gp_nlb_parse_tunnel_info_nodes(info, node->children);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}

static int gp_nlb_parse_tunnel_info_xml(struct openconnect_info *vpninfo,
					xmlNode *xml_node, void *cb_data)
{
	(void)vpninfo;
	return gp_nlb_parse_tunnel_info_nodes(cb_data, xml_node);
}

static int gp_nlb_parse_tunnel_info(struct openconnect_info *vpninfo,
				    const unsigned char *field, int field_len,
				    struct gp_nlb_tunnel_info *info)
{
	unsigned char *decoded = NULL, *plain = NULL;
	char *encoded = NULL;
	int decoded_len = 0, cipher_len = 0, encoded_len = 0, i;
	int ret = -EINVAL;

	encoded = malloc(field_len + 1);
	if (!encoded)
		return -ENOMEM;
	for (i = 0; i < field_len; i++) {
		if (!isspace(field[i]))
			encoded[encoded_len++] = field[i];
	}
	encoded[encoded_len] = '\0';
	decoded = openconnect_base64_decode(&decoded_len, encoded);
	if (!decoded || decoded_len <= GP_NLB_GCM_PREFIX_LEN)
		goto out;
	cipher_len = decoded_len - GP_NLB_GCM_PREFIX_LEN;
	plain = malloc(cipher_len + 1);
	if (!plain) {
		ret = -ENOMEM;
		goto out;
	}
	if (gp_nlb_aes256_gcm_decrypt(vpninfo->gp_nlb.hs_key,
				      decoded + GP_NLB_GCM_TAG_LEN,
				      decoded + GP_NLB_GCM_PREFIX_LEN,
				      cipher_len, decoded, plain) < 0)
		goto out;
	plain[cipher_len] = '\0';
	ret = gpst_xml_or_error(vpninfo, (char *)plain,
				gp_nlb_parse_tunnel_info_xml, NULL, info);

out:
	if (plain) {
		memset(plain, 0, cipher_len + 1);
		free(plain);
	}
	if (decoded) {
		memset(decoded, 0, decoded_len);
		free(decoded);
	}
	free(encoded);
	return ret;
}

static int gp_nlb_replace_ip_option(struct openconnect_info *vpninfo,
				    const char *name, const char *value,
				    const char **ip_info_value)
{
	struct oc_vpn_option *opt;
	char *dup;

	if (!value)
		return 0;
	dup = strdup(value);
	if (!dup)
		return -ENOMEM;

	for (opt = vpninfo->cstp_options; opt; opt = opt->next) {
		if (strcmp(opt->option, name))
			continue;
		free(opt->value);
		opt->value = dup;
		*ip_info_value = dup;
		return 0;
	}

	free(dup);
	*ip_info_value = add_option_dup(&vpninfo->cstp_options,
					name, value, -1);
	return *ip_info_value ? 0 : -ENOMEM;
}

static int gp_nlb_replace_address_options(struct openconnect_info *vpninfo,
					  const char *name, char **values,
					  int count, const char **ip_values)
{
	struct oc_vpn_option *new_opts = NULL, *tail, **opt;
	const char *new_values[3];
	int i;

	if (!count)
		return 0;
	for (i = 0; i < count; i++) {
		new_values[i] = add_option_dup(&new_opts, name, values[i], -1);
		if (!new_values[i]) {
			free_optlist(new_opts);
			return -ENOMEM;
		}
	}

	opt = &vpninfo->cstp_options;
	while (*opt) {
		struct oc_vpn_option *old = *opt;

		if (strcmp(old->option, name)) {
			opt = &old->next;
			continue;
		}
		*opt = old->next;
		old->next = NULL;
		free_optlist(old);
	}

	for (tail = new_opts; tail->next; tail = tail->next)
		;
	tail->next = vpninfo->cstp_options;
	vpninfo->cstp_options = new_opts;
	memset(ip_values, 0, 3 * sizeof(*ip_values));
	for (i = 0; i < count; i++)
		ip_values[i] = new_values[i];
	return 0;
}

static int gp_nlb_commit_tunnel_info(struct openconnect_info *vpninfo,
				     struct gp_nlb_tunnel_info *info)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;
	int ret;

	if (vpninfo->ip_info.addr) {
		if (!info->vip || !info->inner_gw)
			return -EINVAL;
	}
	if (vpninfo->ip_info.addr6) {
		if (!info->vip6 || !info->inner_gw6)
			return -EINVAL;
	}
	if (!vpninfo->ip_info.addr && !vpninfo->ip_info.addr6)
		return -EINVAL;
	ret = gp_nlb_replace_address_options(vpninfo, "DNS", info->dns,
					     info->nr_dns, vpninfo->ip_info.dns);
	if (ret < 0)
		return ret;
	ret = gp_nlb_replace_address_options(vpninfo, "WINS", info->wins,
					     info->nr_wins, vpninfo->ip_info.nbns);
	if (ret < 0)
		return ret;

	free(nlb->tunnel_vip);
	free(nlb->tunnel_vip6);
	free(nlb->inner_gw_ip);
	free(nlb->inner_gw_ip6);
	nlb->tunnel_vip = info->vip;
	nlb->tunnel_vip6 = info->vip6;
	nlb->inner_gw_ip = info->inner_gw;
	nlb->inner_gw_ip6 = info->inner_gw6;
	info->vip = NULL;
	info->vip6 = NULL;
	info->inner_gw = NULL;
	info->inner_gw6 = NULL;
	return 0;
}

static int gp_nlb_is_tunnel_response(const unsigned char *buf, int len)
{
	if (!buf || len < 8)
		return 0;
	if (!memcmp(buf + 4, gp_nlb_response_magic, sizeof(gp_nlb_response_magic)))
		return 1;
	return len >= GP_NLB_CONTROL_HEADER_LEN && !load_be32(buf) &&
		memcmp(buf + 4, gp_nlb_request_magic, sizeof(gp_nlb_request_magic));
}

int gpst_nlb_handle_tunnel_response(struct openconnect_info *vpninfo,
				    const unsigned char *buf, int len)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;
	struct gp_nlb_tunnel_info info = { 0 };
	int count, i, found_info = 0, ret = -EINVAL;

	if (!nlb->enabled || !gp_nlb_is_tunnel_response(buf, len))
		return 0;
	if (len < GP_NLB_CONTROL_HEADER_LEN)
		return -EINVAL;
	count = buf[16];
	if (count > (len - GP_NLB_CONTROL_HEADER_LEN) / GP_NLB_TOC_ENTRY_LEN)
		return -EINVAL;

	for (i = 0; i < count; i++) {
		const unsigned char *entry = buf + GP_NLB_CONTROL_HEADER_LEN +
			i * GP_NLB_TOC_ENTRY_LEN;
		int offset = load_be16(entry + 1);
		int value_len = load_be16(entry + 3);

		if (offset > len || value_len > len - offset)
			goto out;
		if (entry[0] == GP_NLB_BLOCK_TUNNEL_INFO) {
			if (found_info)
				goto out;
			found_info = 1;
			ret = gp_nlb_parse_tunnel_info(vpninfo, buf + offset,
						       value_len, &info);
			if (ret < 0)
				goto out;
		}
	}

	if (!found_info)
		goto out;
	ret = gp_nlb_commit_tunnel_info(vpninfo, &info);
	if (ret < 0)
		goto out;

	ret = gpst_nlb_apply_tunnel_config(vpninfo);
	if (ret < 0)
		goto out;
	nlb->control_state = GP_NLB_CONTROL_READY;
	nlb->keepalive_sent = 0;
	vpn_progress(vpninfo, PRG_INFO,
		     _("NLB tunnel-control established: vip=%s inner_gw=%s\n"),
		     nlb->tunnel_vip ?: "unknown", nlb->inner_gw_ip ?: "unknown");
	ret = 1;

out:
	gp_nlb_free_tunnel_info(&info);
	return ret;
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

	/* Trim trailing CR/LF. */
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
	if (!start)
		goto out;
	*start = '\0';
	hash = strrchr(line, ' ');
	if (!hash || strlen(hash + 1) != 40)
		goto out;
	*hash++ = '\0';

	if (sscanf(line, "%ld", &version) != 1 || version != GP_NLB_SSL_PROTO_VERSION)
		goto out;
	concat = strchr(line, ' ');
	if (!concat)
		goto out;
	concat++;

	hint_vip = nlb->tunnel_vip;
	if (gp_nlb_split_concat_ips(concat, hint_vip, &vip, &inner))
		goto out;

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

static int gp_nlb_route_list_contains(struct oc_split_include *list,
				      const char *route)
{
	for (; list; list = list->next) {
		if (list->route && !strcmp(list->route, route))
			return 1;
	}
	return 0;
}

static int gpst_nlb_update_esp_magic(struct openconnect_info *vpninfo)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;
	const char *gateway6 = nlb->inner_gw_ip6 ?: nlb->tunnel_vip6;
	const char *gateway = nlb->inner_gw_ip ?: nlb->tunnel_vip;
	struct in6_addr addr6;
	struct in_addr addr;

	if (gateway6 && (vpninfo->esp_magic_af == AF_INET6 || !gateway) &&
	    inet_pton(AF_INET6, gateway6, &addr6) == 1) {
		vpninfo->esp_magic_af = AF_INET6;
		memcpy(vpninfo->esp_magic, &addr6, sizeof(addr6));
		return 0;
	}
	if (!gateway || inet_pton(AF_INET, gateway, &addr) != 1)
		return 0;
	vpninfo->esp_magic_af = AF_INET;
	memcpy(vpninfo->esp_magic, &addr, sizeof(addr));
	return 0;
}

static int gp_nlb_add_private_route(struct openconnect_info *vpninfo,
				    const char *ip, int prefix)
{
	struct oc_split_include *inc;
	char route[80];

	if (!ip)
		return 0;
	if (snprintf(route, sizeof(route), "%s/%d", ip, prefix) >= (int)sizeof(route))
		return -EINVAL;
	if (gp_nlb_route_list_contains(vpninfo->ip_info.split_includes, route))
		return 0;

	inc = malloc(sizeof(*inc));
	if (!inc)
		return -ENOMEM;
	inc->route = add_option_dup(&vpninfo->cstp_options,
				    "split-include", route, -1);
	if (!inc->route) {
		free(inc);
		return -ENOMEM;
	}
	inc->next = vpninfo->ip_info.split_includes;
	vpninfo->ip_info.split_includes = inc;
	vpn_progress(vpninfo, PRG_INFO,
		     _("NLB: add an access route for NLB private ip: %s.\n"),
		     ip);
	return 0;
}

int gpst_nlb_apply_routes(struct openconnect_info *vpninfo)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;
	int ret;

	if (!nlb->enabled)
		return 0;
	ret = gp_nlb_add_private_route(vpninfo, nlb->inner_gw_ip, 32);
	if (ret < 0)
		return ret;
	return gp_nlb_add_private_route(vpninfo, nlb->inner_gw_ip6, 128);
}

int gpst_nlb_apply_tunnel_config(struct openconnect_info *vpninfo)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;
	int ret;

	if (vpninfo->ip_info.addr && nlb->tunnel_vip) {
		ret = gp_nlb_replace_ip_option(vpninfo, "ipaddr", nlb->tunnel_vip,
					       &vpninfo->ip_info.addr);
		if (ret < 0)
			return ret;
	}
	if (vpninfo->ip_info.addr6 && nlb->tunnel_vip6) {
		ret = gp_nlb_replace_ip_option(vpninfo, "ipaddr6", nlb->tunnel_vip6,
					       &vpninfo->ip_info.addr6);
		if (ret < 0)
			return ret;
	}
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
	vpninfo->dtls_need_reconnect = 1;
	return 1;
}

int gpst_nlb_handle_ssl_connect_response(struct openconnect_info *vpninfo,
					 const char *buf, int len)
{
	static const char start_tunnel[] = "START_TUNNEL";

	if (!buf || len <= 0)
		return -EINVAL;
	if (len >= 12 && !strncmp(buf, start_tunnel, 12)) {
		vpn_progress(vpninfo, PRG_INFO,
			     _("NLB SSL tunnel response: START_TUNNEL len=%d\n"), len);
		return gpst_nlb_apply_tunnel_config(vpninfo);
	}
	if (!strstr(buf, start_tunnel))
		return -EINVAL;
	if (gpst_nlb_parse_ssl_response(buf, len, &vpninfo->gp_nlb) < 0)
		return -EINVAL;

	vpn_progress(vpninfo, PRG_INFO,
		     _("NLB SSL tunnel response: vip=%s inner_gw=%s cert_hash=%s\n"),
		     vpninfo->gp_nlb.tunnel_vip ?: "unknown",
		     vpninfo->gp_nlb.inner_gw_ip ?: "unknown",
		     vpninfo->gp_nlb.in_tunnel_gw_cert_chksum ? "present" : "missing");
	return gpst_nlb_apply_tunnel_config(vpninfo);
}
