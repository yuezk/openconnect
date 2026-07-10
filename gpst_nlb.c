/*
 * GlobalProtect NLB (Network Load Balancer) tunnel support
 *
 * PanGPS performs a separate UDP tunnel-control exchange before it sends
 * normal ESP traffic to an NLB gateway:
 *
 *   1. getconfig.esp returns hs-key, enc-hs-key, and tunnel-opaque.
 *   2. The client sends a GPTC control packet containing the two opaque
 *      values, encrypted preferred-address data, and a fixed client hash.
 *   3. The gateway returns a zero-prefixed or CTPG packet. Its type-4 field
 *      contains base64(tag[16] || iv[12] || AES-256-GCM ciphertext),
 *      encrypted with the clear hs-key from getconfig.esp.
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
#include "gpst_nlb.h"

#define GP_NLB_CONTROL_MAX		2048
#define GP_NLB_TOC_ENTRY_LEN		5
#define GP_NLB_TOC_COUNT		4
#define GP_NLB_BLOCK_ENC_HS_KEY		1
#define GP_NLB_BLOCK_TUNNEL_OPAQUE	2
#define GP_NLB_BLOCK_TUNNEL_INFO	4
#define GP_NLB_BLOCK_CLIENT_HASH	5
#define GP_NLB_GCM_TAG_LEN		16
#define GP_NLB_GCM_IV_LEN		12
#define GP_NLB_GCM_PREFIX_LEN		(GP_NLB_GCM_TAG_LEN + GP_NLB_GCM_IV_LEN)
#define GP_NLB_MAX_DNS			3
#define GP_NLB_MAX_WINS			2

#define GP_NLB_CONTROL_PENDING		1
#define GP_NLB_CONTROL_WAITING		2
#define GP_NLB_CONTROL_READY		3
#define GP_NLB_CONTROL_RESTORING	4
#define GP_NLB_CONTROL_FAILED		5
#define GP_NLB_CONTROL_MAX_REQUESTS	3
#define GP_NLB_RESTORE_WAIT		2

#define GP_NLB_SSL_IPV4_VIP_OFFSET	4
#define GP_NLB_SSL_IPV4_GW_OFFSET	19
#define GP_NLB_SSL_IPV4_FIELD_LEN	15
#define GP_NLB_SSL_IPV6_RESPONSE_LEN	188
#define GP_NLB_SSL_IPV6_VIP_OFFSET	98
#define GP_NLB_SSL_IPV6_GW_OFFSET	137
#define GP_NLB_SSL_IPV6_FIELD_LEN	39

static const unsigned char gp_nlb_request_magic[4] = { 'G', 'P', 'T', 'C' };
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
	char *dns[GP_NLB_MAX_DNS];
	char *wins[GP_NLB_MAX_WINS];
	int nr_dns;
	int nr_wins;
	int dns_present;
	int wins_present;
	int dns_v6;
	int wins_v6;
};

static int gp_nlb_is_ipv4(const char *s)
{
	struct in_addr a;

	return s && inet_pton(AF_INET, s, &a) == 1;
}

int gpst_nlb_prepare(struct openconnect_info *vpninfo)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;
	struct in_addr vip;

	if (!nlb->enabled)
		return 0;

	nlb->control_state = GP_NLB_CONTROL_PENDING;
	nlb->last_nlb_send = 0;
	nlb->control_requests = 0;
	nlb->keepalive_sent = 0;
	nlb->keepalive_seq = 0;

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
		     _("NLB tunnel control ready: vip=%s connected_gw=%s hs_key=%d bytes enc_hs_key=%zu bytes tunnel_opaque=%zu bytes opaque_valid_for=%llds\n"),
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

	if (!nlb->enabled || nlb->control_state == GP_NLB_CONTROL_READY ||
	    nlb->control_state == GP_NLB_CONTROL_RESTORING ||
	    nlb->control_state == GP_NLB_CONTROL_FAILED)
		return 0;
	if (vpninfo->dtls_fd < 0)
		return -EINVAL;
	if (nlb->control_state == GP_NLB_CONTROL_WAITING &&
	    nlb->last_nlb_send == now)
		return 0;
	if (nlb->control_requests >= GP_NLB_CONTROL_MAX_REQUESTS) {
		nlb->control_state = GP_NLB_CONTROL_FAILED;
		vpn_progress(vpninfo, PRG_ERR,
			     _("NLB tunnel-control failed: no valid response after %u requests\n"),
			     nlb->control_requests);
		return 0;
	}

	len = gp_nlb_build_tunnel_request(vpninfo, request, sizeof(request));
	if (len < 0)
		return len;
	ret = send(vpninfo->dtls_fd, request, len, 0);
	if (ret != len)
		return ret < 0 ? -errno : -EIO;

	nlb->control_state = GP_NLB_CONTROL_WAITING;
	nlb->last_nlb_send = now;
	nlb->control_requests++;
	time(&vpninfo->dtls_times.last_tx);
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Sent NLB tunnel-control request %u (%d bytes)\n"),
		     nlb->control_requests, len);
	return 0;
}

#ifdef HAVE_ESP
int gpst_nlb_restore(struct openconnect_info *vpninfo)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;
	time_t now = time(NULL);
	int ret;

	if (!nlb->enabled || nlb->control_state != GP_NLB_CONTROL_RESTORING)
		return 0;

	if (!nlb->last_nlb_send) {
		ret = gpst_nlb_send_esp_keepalive(vpninfo);
		if (ret < 0) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("NLB restoration keepalive failed; restarting tunnel control\n"));
			nlb->control_state = GP_NLB_CONTROL_PENDING;
			nlb->control_requests = 0;
			return 0;
		}
		nlb->last_nlb_send = now;
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Sent NLB restoration keepalive; waiting %d seconds for ESP response\n"),
			     GP_NLB_RESTORE_WAIT);
		return 1;
	}

	if (now < nlb->last_nlb_send + GP_NLB_RESTORE_WAIT)
		return 1;

	vpn_progress(vpninfo, PRG_INFO,
		     _("NLB restoration keepalive timed out; restarting tunnel control\n"));
	nlb->control_state = GP_NLB_CONTROL_PENDING;
	nlb->last_nlb_send = 0;
	nlb->control_requests = 0;
	return 0;
}

void gpst_nlb_udp_closed(struct openconnect_info *vpninfo)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;

	if (!nlb->enabled)
		return;

	if (nlb->control_state == GP_NLB_CONTROL_READY) {
		nlb->control_state = GP_NLB_CONTROL_RESTORING;
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("NLB UDP socket closed; restoration will try ESP before tunnel control\n"));
	} else if (nlb->control_state != GP_NLB_CONTROL_RESTORING) {
		nlb->control_state = GP_NLB_CONTROL_PENDING;
	}
	nlb->last_nlb_send = 0;
	nlb->control_requests = 0;
	nlb->keepalive_sent = 0;
}

void gpst_nlb_restore_complete(struct openconnect_info *vpninfo)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;

	if (!nlb->enabled || nlb->control_state != GP_NLB_CONTROL_RESTORING)
		return;
	nlb->control_state = GP_NLB_CONTROL_READY;
	nlb->last_nlb_send = 0;
	nlb->keepalive_sent = 1;
	vpn_progress(vpninfo, PRG_INFO,
		     _("NLB tunnel restored by ESP keepalive; tunnel-control exchange not required\n"));
}
#endif /* HAVE_ESP */

void gpst_nlb_report_timeout(struct openconnect_info *vpninfo)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;

	if (!nlb->enabled)
		return;
	if (nlb->control_state == GP_NLB_CONTROL_READY)
		vpn_progress(vpninfo, PRG_ERR,
			     _("NLB tunnel control succeeded, but no valid ESP keepalive response was received\n"));
	else if (nlb->control_state == GP_NLB_CONTROL_RESTORING)
		vpn_progress(vpninfo, PRG_ERR,
			     _("NLB tunnel restoration did not receive a valid ESP response\n"));
	else
		vpn_progress(vpninfo, PRG_ERR,
			     _("NLB tunnel control did not complete after %u request(s)\n"),
			     nlb->control_requests);
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

static void gp_nlb_clear_address_list(char **values, int *count)
{
	int i;

	for (i = 0; i < *count; i++) {
		free(values[i]);
		values[i] = NULL;
	}
	*count = 0;
}

static int gp_nlb_parse_address_list(xmlNode *node, char **values, int *count,
				     int max_count)
{
	xmlNode *member;
	char *s = NULL;

	for (member = node->children; member && *count < max_count;
	     member = member->next) {
		if (xmlnode_get_val(member, "member", &s))
			continue;
		values[(*count)++] = s;
		s = NULL;
	}
	free(s);
	return 0;
}

static int gp_nlb_replace_address_list(xmlNode *node, char **values, int *count,
				       int max_count)
{
	gp_nlb_clear_address_list(values, count);
	return gp_nlb_parse_address_list(node, values, count, max_count);
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
		} else if (xmlnode_is_named(node, "dns-v6")) {
			info->dns_present = info->dns_v6 = 1;
			ret = gp_nlb_replace_address_list(node, info->dns, &info->nr_dns,
						  GP_NLB_MAX_DNS);
		} else if (xmlnode_is_named(node, "dns") && !info->dns_v6) {
			info->dns_present = 1;
			ret = gp_nlb_replace_address_list(node, info->dns, &info->nr_dns,
						  GP_NLB_MAX_DNS);
		} else if (xmlnode_is_named(node, "wins-v6")) {
			info->wins_present = info->wins_v6 = 1;
			ret = gp_nlb_replace_address_list(node, info->wins, &info->nr_wins,
						  GP_NLB_MAX_WINS);
		} else if (xmlnode_is_named(node, "wins") && !info->wins_v6) {
			info->wins_present = 1;
			ret = gp_nlb_replace_address_list(node, info->wins, &info->nr_wins,
						  GP_NLB_MAX_WINS);
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
	if (!xmlnode_is_named(xml_node, "response") ||
	    xmlnode_match_prop(xml_node, "status", "success"))
		return -EINVAL;
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
	if (!decoded || decoded_len <= GP_NLB_GCM_PREFIX_LEN) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("NLB tunnel-control response has invalid base64 tunnel info: encoded=%d decoded=%d\n"),
			     encoded_len, decoded_len);
		goto out;
	}
	cipher_len = decoded_len - GP_NLB_GCM_PREFIX_LEN;
	plain = malloc(cipher_len + 1);
	if (!plain) {
		ret = -ENOMEM;
		goto out;
	}
	if (gp_nlb_aes256_gcm_decrypt(vpninfo->gp_nlb.hs_key,
				      decoded + GP_NLB_GCM_TAG_LEN,
				      decoded + GP_NLB_GCM_PREFIX_LEN,
				      cipher_len, decoded, plain) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("NLB tunnel-control response failed AES-256-GCM authentication: cipher=%d bytes\n"),
			     cipher_len);
		goto out;
	}
	plain[cipher_len] = '\0';
	ret = gpst_xml_or_error(vpninfo, (char *)plain,
				gp_nlb_parse_tunnel_info_xml, NULL, info);
	if (ret < 0)
		vpn_progress(vpninfo, PRG_ERR,
			     _("NLB tunnel-control response contains invalid tunnel-info XML\n"));

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
					  int count, int present,
					  const char **ip_values)
{
	struct oc_vpn_option *new_opts = NULL, *tail, **opt;
	const char *new_values[3];
	int i;

	if (!present)
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

	if (new_opts) {
		for (tail = new_opts; tail->next; tail = tail->next)
			;
		tail->next = vpninfo->cstp_options;
		vpninfo->cstp_options = new_opts;
	}
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
		if (!info->vip || !info->inner_gw) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("NLB tunnel-control response is missing the IPv4 VIP or private gateway\n"));
			return -EINVAL;
		}
	}
	if (vpninfo->ip_info.addr6) {
		if (!info->vip6 || !info->inner_gw6) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("NLB tunnel-control response is missing the IPv6 VIP or private gateway\n"));
			return -EINVAL;
		}
	}
	if (!vpninfo->ip_info.addr && !vpninfo->ip_info.addr6)
		return -EINVAL;
	ret = gp_nlb_replace_address_options(vpninfo, "DNS", info->dns,
					     info->nr_dns, info->dns_present,
					     vpninfo->ip_info.dns);
	if (ret < 0)
		return ret;
	ret = gp_nlb_replace_address_options(vpninfo, "WINS", info->wins,
					     info->nr_wins, info->wins_present,
					     vpninfo->ip_info.nbns);
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

int gpst_nlb_handle_tunnel_response(struct openconnect_info *vpninfo,
				    const unsigned char *buf, int len)
{
	struct gp_nlb_config *nlb = &vpninfo->gp_nlb;
	struct gp_nlb_tunnel_info info = { 0 };
	int count, toc_end, i, found_info = 0, ret = -EINVAL;

	if (!nlb->enabled || nlb->control_state != GP_NLB_CONTROL_WAITING)
		return 0;
	if (!gp_nlb_is_tunnel_response(buf, len)) {
		if (buf && len >= 8)
			vpn_progress(vpninfo, PRG_ERR,
				     _("NLB tunnel-control received unexpected datagram: len=%d word0=0x%08x marker=%02x%02x%02x%02x\n"),
				     len, load_be32(buf), buf[4], buf[5], buf[6], buf[7]);
		else
			vpn_progress(vpninfo, PRG_ERR,
				     _("NLB tunnel-control received a truncated datagram: len=%d\n"), len);
		return -EPROTO;
	}

	count = buf[16];
	if (count > (len - GP_NLB_CONTROL_HEADER_LEN) / GP_NLB_TOC_ENTRY_LEN) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("NLB tunnel-control response has truncated TOC: len=%d count=%d\n"),
			     len, count);
		return -EINVAL;
	}
	toc_end = GP_NLB_CONTROL_HEADER_LEN + count * GP_NLB_TOC_ENTRY_LEN;
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Received NLB tunnel-control response: len=%d framing=%s toc_count=%d\n"),
		     len, !load_be32(buf) ? "zero-prefix" : "CTPG", count);

	for (i = 0; i < count; i++) {
		const unsigned char *entry = buf + GP_NLB_CONTROL_HEADER_LEN +
			i * GP_NLB_TOC_ENTRY_LEN;
		int offset = load_be16(entry + 1);
		int value_len = load_be16(entry + 3);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("NLB tunnel-control TOC entry %d: type=%u offset=%d len=%d\n"),
			     i, entry[0], offset, value_len);
		if (offset < toc_end || offset > len || value_len > len - offset) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("NLB tunnel-control TOC entry %d is out of bounds: payload_start=%d offset=%d len=%d datagram=%d\n"),
				     i, toc_end, offset, value_len, len);
			goto out;
		}
		if (entry[0] == GP_NLB_BLOCK_TUNNEL_INFO) {
			if (found_info) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("NLB tunnel-control response contains duplicate tunnel-info fields\n"));
				goto out;
			}
			found_info = 1;
			ret = gp_nlb_parse_tunnel_info(vpninfo, buf + offset,
						       value_len, &info);
			if (ret < 0)
				goto out;
		}
	}

	if (!found_info) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("NLB tunnel-control response does not contain tunnel info\n"));
		goto out;
	}
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("NLB tunnel-info verified: ipv4=%s ipv6=%s dns=%d%s wins=%d%s\n"),
		     info.vip && info.inner_gw ? "yes" : "no",
		     info.vip6 && info.inner_gw6 ? "yes" : "no",
		     info.nr_dns, info.dns_v6 ? " (IPv6)" : "",
		     info.nr_wins, info.wins_v6 ? " (IPv6)" : "");
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

static int gp_nlb_copy_ssl_ip(const char *line, int line_len, int offset,
			      int field_len, int af, char **out)
{
	char field[INET6_ADDRSTRLEN];
	char *end;

	if (field_len >= (int)sizeof(field) || offset > line_len ||
	    field_len > line_len - offset)
		return -EINVAL;
	memcpy(field, line + offset, field_len);
	field[field_len] = '\0';
	end = field + field_len;
	while (end > field && isspace((unsigned char)end[-1]))
		*--end = '\0';
	if ((af == AF_INET && !gp_nlb_is_ipv4(field)) ||
	    (af == AF_INET6 && !gp_nlb_is_ipv6(field)))
		return -EINVAL;
	*out = strdup(field);
	return *out ? 0 : -ENOMEM;
}

int gpst_nlb_parse_ssl_response(const char *buf, int len, struct gp_nlb_config *nlb)
{
	char *line, *vip = NULL, *inner = NULL, *vip6 = NULL, *inner6 = NULL;
	int line_len, ret = -EINVAL;

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

	line_len = strlen(line);
	if (line_len == 12 && !memcmp(line, "START_TUNNEL", 12)) {
		ret = 0;
		goto out;
	}
	if (line_len < GP_NLB_SSL_IPV4_GW_OFFSET + GP_NLB_SSL_IPV4_FIELD_LEN ||
	    strncmp(line, "110 ", 4) || !strstr(line, "START_TUNNEL"))
		goto out;
	ret = gp_nlb_copy_ssl_ip(line, line_len, GP_NLB_SSL_IPV4_VIP_OFFSET,
				 GP_NLB_SSL_IPV4_FIELD_LEN, AF_INET, &vip);
	if (ret < 0)
		goto out;
	ret = gp_nlb_copy_ssl_ip(line, line_len, GP_NLB_SSL_IPV4_GW_OFFSET,
				 GP_NLB_SSL_IPV4_FIELD_LEN, AF_INET, &inner);
	if (ret < 0)
		goto out;

	if (line_len == GP_NLB_SSL_IPV6_RESPONSE_LEN) {
		ret = gp_nlb_copy_ssl_ip(line, line_len, GP_NLB_SSL_IPV6_VIP_OFFSET,
					 GP_NLB_SSL_IPV6_FIELD_LEN, AF_INET6, &vip6);
		if (ret < 0)
			goto out;
		ret = gp_nlb_copy_ssl_ip(line, line_len, GP_NLB_SSL_IPV6_GW_OFFSET,
					 GP_NLB_SSL_IPV6_FIELD_LEN, AF_INET6, &inner6);
		if (ret < 0)
			goto out;
	}

	free(nlb->tunnel_vip);
	free(nlb->tunnel_vip6);
	free(nlb->inner_gw_ip);
	free(nlb->inner_gw_ip6);
	nlb->tunnel_vip = vip;
	nlb->tunnel_vip6 = vip6;
	nlb->inner_gw_ip = inner;
	nlb->inner_gw_ip6 = inner6;
	vip = inner = vip6 = inner6 = NULL;
	nlb->enabled = 1;
	ret = 0;

out:
	free(vip);
	free(inner);
	free(vip6);
	free(inner6);
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
		     _("NLB SSL tunnel response: vip=%s inner_gw=%s ipv6=%s cert_hash=%s\n"),
		     vpninfo->gp_nlb.tunnel_vip ?: "unknown",
		     vpninfo->gp_nlb.inner_gw_ip ?: "unknown",
		     vpninfo->gp_nlb.tunnel_vip6 && vpninfo->gp_nlb.inner_gw_ip6 ?
			     "present" : "absent",
		     vpninfo->gp_nlb.in_tunnel_gw_cert_chksum ? "present" : "missing");
	return gpst_nlb_apply_tunnel_config(vpninfo);
}
