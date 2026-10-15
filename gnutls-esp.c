/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <config.h>

#include "openconnect-internal.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <unistd.h>

#include <string.h>
#include <stdlib.h>
#include <errno.h>

void destroy_esp_ciphers(struct esp *esp)
{
	if (esp->cipher) {
		gnutls_cipher_deinit(esp->cipher);
		esp->cipher = NULL;
	}
	if (esp->hmac) {
		gnutls_hmac_deinit(esp->hmac, NULL);
		esp->hmac = NULL;
	}
}

static int init_esp_cipher(struct openconnect_info *vpninfo, struct esp *esp,
			   gnutls_mac_algorithm_t macalg, gnutls_cipher_algorithm_t encalg,
			   int gcm)
{
	gnutls_datum_t enc_key;
	int err;

	destroy_esp_ciphers(esp);

	if (gcm)
		return 0;

	enc_key.size = gnutls_cipher_get_key_size(encalg);
	enc_key.data = esp->enc_key;

	err = gnutls_cipher_init(&esp->cipher, encalg, &enc_key, NULL);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialise ESP cipher: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}

	err = gnutls_hmac_init(&esp->hmac, macalg,
			       esp->hmac_key,
			       vpninfo->hmac_key_len);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialize ESP HMAC: %s\n"),
			     gnutls_strerror(err));
		destroy_esp_ciphers(esp);
		return -EIO;
	}
	return 0;
}

static gnutls_cipher_algorithm_t esp_gcm_cipher(const struct openconnect_info *vpninfo)
{
	return vpninfo->esp_enc == ENC_AES_256_GCM ?
		GNUTLS_CIPHER_AES_256_GCM : GNUTLS_CIPHER_AES_128_GCM;
}

static int esp_gcm_init(struct openconnect_info *vpninfo, gnutls_cipher_hd_t *hd,
			const unsigned char *key, const unsigned char *iv, uint32_t seq)
{
	gnutls_datum_t enc_key, iv_d;
	unsigned char nonce[12];
	gnutls_cipher_algorithm_t encalg = esp_gcm_cipher(vpninfo);
	int err;

	enc_key.data = (unsigned char *)key;
	enc_key.size = esp_gcm_cipher_key_len(vpninfo);
	esp_gcm_nonce(nonce, key, vpninfo, iv, seq);
	iv_d.data = nonce;
	iv_d.size = sizeof(nonce);

	err = gnutls_cipher_init(hd, encalg, &enc_key, &iv_d);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to init ESP GCM cipher: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}
	return 0;
}

static gnutls_mac_algorithm_t esp_gcm_macalg(const struct openconnect_info *vpninfo)
{
	switch (vpninfo->esp_hmac) {
	case HMAC_MD5:
		return GNUTLS_MAC_MD5;
	case HMAC_SHA1:
		return GNUTLS_MAC_SHA1;
	case HMAC_SHA256:
		return GNUTLS_MAC_SHA256;
	default:
		return 0;
	}
}

static int esp_gcm_hmac(const struct openconnect_info *vpninfo, const struct esp *esp,
			const void *data, int len, unsigned char *out)
{
	gnutls_mac_algorithm_t macalg = esp_gcm_macalg(vpninfo);
	int auth_len = esp_gcm_auth_len(vpninfo);
	int err;

	if (!auth_len)
		return 0;
	if (!macalg)
		return -EINVAL;

	err = gnutls_hmac_fast(macalg, esp->hmac_key, vpninfo->hmac_key_len,
			       data, len, out);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to calculate HMAC for ESP GCM packet: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}
	return auth_len;
}

/* pkt->data sits after a 24-byte ESP prefix but the on-wire header is only
 * 16 bytes, so HMAC must cover the wire header and ciphertext separately. */
static int esp_gcm_hmac_pkt(const struct openconnect_info *vpninfo, const struct esp *esp,
			    const struct pkt *pkt, int crypt_len, unsigned char *out)
{
	gnutls_mac_algorithm_t macalg = esp_gcm_macalg(vpninfo);
	gnutls_hmac_hd_t hd = NULL;
	int auth_len = esp_gcm_auth_len(vpninfo);
	int err;

	if (!auth_len)
		return 0;
	if (!macalg)
		return -EINVAL;

	err = gnutls_hmac_init(&hd, macalg, esp->hmac_key, vpninfo->hmac_key_len);
	if (err)
		goto fail;
	err = gnutls_hmac(hd, &pkt->esp, esp_wire_hdr_len(vpninfo));
	if (err)
		goto fail;
	err = gnutls_hmac(hd, pkt->data, crypt_len);
	if (err)
		goto fail;
	gnutls_hmac_output(hd, out);
	gnutls_hmac_deinit(hd, NULL);
	return auth_len;

fail:
	if (hd)
		gnutls_hmac_deinit(hd, NULL);
	vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to calculate HMAC for ESP GCM packet: %s\n"),
		     gnutls_strerror(err));
	return -EIO;
}

int esp_gcm_auth_outgoing(struct openconnect_info *vpninfo, struct pkt *pkt, int crypt_len)
{
	unsigned char hmac_buf[MAX_HMAC_SIZE];
	int auth_len = esp_gcm_auth_len(vpninfo);
	int hdr = esp_wire_hdr_len(vpninfo);
	unsigned char *out;

	if (!auth_len)
		return 0;

	if (esp_gcm_hmac(vpninfo, &vpninfo->esp_out, &pkt->esp, hdr + crypt_len,
			 hmac_buf) < 0)
		return -EIO;

	out = (unsigned char *)&pkt->esp + hdr + crypt_len + vpninfo->esp_gcm_icv;
	memcpy(out, hmac_buf, auth_len);
	return 0;
}

static int esp_gcm_aad(struct openconnect_info *vpninfo, gnutls_cipher_hd_t hd,
		       const struct pkt *pkt)
{
	unsigned char aad[8];
	int err;

	memcpy(aad, &pkt->esp.spi, 8);
	err = gnutls_cipher_add_auth(hd, aad, sizeof(aad));
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set ESP GCM AAD: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}
	return 0;
}

int init_esp_ciphers(struct openconnect_info *vpninfo, struct esp *esp_out, struct esp *esp_in)
{
	gnutls_mac_algorithm_t macalg = 0;
	gnutls_cipher_algorithm_t encalg;
	int gcm = esp_uses_gcm(vpninfo);
	int ret;

	switch (vpninfo->esp_enc) {
	case ENC_AES_128_CBC:
		encalg = GNUTLS_CIPHER_AES_128_CBC;
		break;
	case ENC_AES_256_CBC:
		encalg = GNUTLS_CIPHER_AES_256_CBC;
		break;
	case ENC_AES_128_GCM:
	case ENC_AES_256_GCM:
		encalg = esp_gcm_cipher(vpninfo);
		break;
	default:
		return -EINVAL;
	}

	if (vpninfo->esp_hmac) {
		switch (vpninfo->esp_hmac) {
		case HMAC_MD5:
			macalg = GNUTLS_MAC_MD5;
			break;
		case HMAC_SHA1:
			macalg = GNUTLS_MAC_SHA1;
			break;
		case HMAC_SHA256:
			macalg = GNUTLS_MAC_SHA256;
			break;
		default:
			if (!gcm)
				return -EINVAL;
			macalg = 0;
			break;
		}
	} else if (!gcm) {
		return -EINVAL;
	}

	ret = init_esp_cipher(vpninfo, esp_out, macalg, encalg, gcm);
	if (ret)
		return ret;

	if (!gcm)
		gnutls_cipher_set_iv(esp_out->cipher, esp_out->iv, sizeof(esp_out->iv));

	ret = init_esp_cipher(vpninfo, esp_in, macalg, encalg, gcm);
	if (ret) {
		destroy_esp_ciphers(esp_out);
		return ret;
	}

	return 0;
}

/* pkt->len shall be the *payload* length. Omitting the header and the ICV/HMAC */
int decrypt_esp_packet(struct openconnect_info *vpninfo, struct esp *esp, struct pkt *pkt)
{
	unsigned char hmac_buf[MAX_HMAC_SIZE];
	gnutls_cipher_hd_t hd = NULL;
	int err;

	if (verify_packet_seqno(vpninfo, esp, ntohl(pkt->esp.seq)))
		return -EINVAL;

	if (esp_uses_gcm(vpninfo)) {
		int icv_len = vpninfo->esp_gcm_icv;
		int auth_len = esp_gcm_auth_len(vpninfo);

		if (pkt->len < icv_len + auth_len)
			return -EINVAL;

		if (auth_len) {
			if (esp_gcm_hmac_pkt(vpninfo, esp, pkt,
					     pkt->len - icv_len - auth_len,
					     hmac_buf) < 0)
				return -EIO;
			if (memcmp(hmac_buf, pkt->data + pkt->len - auth_len, auth_len)) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Received ESP GCM packet with invalid HMAC\n"));
				return -EINVAL;
			}
		}

		pkt->len -= icv_len + auth_len;

		if (esp_gcm_init(vpninfo, &hd, esp->enc_key, pkt->esp.iv, pkt->esp.seq))
			return -EIO;
		if (esp_gcm_aad(vpninfo, hd, pkt))
			goto gcm_fail;

		err = gnutls_cipher_decrypt(hd, pkt->data, pkt->len);
		if (err) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Decrypting ESP GCM packet failed: %s\n"),
				     gnutls_strerror(err));
			goto gcm_fail;
		}

		err = gnutls_cipher_tag(hd, hmac_buf, icv_len);
		if (err ||
		    memcmp(hmac_buf, pkt->data + pkt->len, icv_len)) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received ESP GCM packet with invalid ICV\n"));
			goto gcm_fail;
		}

		gnutls_cipher_deinit(hd);
		return 0;

	gcm_fail:
		gnutls_cipher_deinit(hd);
		return -EINVAL;
	}

	err = gnutls_hmac(esp->hmac, &pkt->esp, sizeof(pkt->esp) + pkt->len);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to calculate HMAC for ESP packet: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}
	gnutls_hmac_output(esp->hmac, hmac_buf);
	if (memcmp(hmac_buf, pkt->data + pkt->len, vpninfo->hmac_out_len)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received ESP packet with invalid HMAC\n"));
		return -EINVAL;
	}

	gnutls_cipher_set_iv(esp->cipher, pkt->esp.iv, sizeof(pkt->esp.iv));

	err = gnutls_cipher_decrypt(esp->cipher, pkt->data, pkt->len);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Decrypting ESP packet failed: %s\n"),
			     gnutls_strerror(err));
		return -EINVAL;
	}

	return 0;
}

int encrypt_esp_packet(struct openconnect_info *vpninfo, struct pkt *pkt, int crypt_len)
{
	const int blksize = 16;
	gnutls_cipher_hd_t hd = NULL;
	int err;

	if (esp_uses_gcm(vpninfo)) {
		if (esp_gcm_init(vpninfo, &hd, vpninfo->esp_out.enc_key, pkt->esp.iv, pkt->esp.seq))
			return -EIO;
		if (esp_gcm_aad(vpninfo, hd, pkt))
			goto gcm_enc_fail;

		err = gnutls_cipher_encrypt(hd, pkt->data, crypt_len);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to encrypt ESP GCM packet: %s\n"),
				     gnutls_strerror(err));
			goto gcm_enc_fail;
		}

		err = gnutls_cipher_tag(hd, pkt->data + crypt_len, vpninfo->esp_gcm_icv);
		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to fetch ESP GCM ICV: %s\n"),
				     gnutls_strerror(err));
			goto gcm_enc_fail;
		}

		gnutls_cipher_deinit(hd);
		return 0;

	gcm_enc_fail:
		gnutls_cipher_deinit(hd);
		return -EIO;
	}

	err = gnutls_cipher_encrypt(vpninfo->esp_out.cipher, pkt->data, crypt_len);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to encrypt ESP packet: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}

	err = gnutls_hmac(vpninfo->esp_out.hmac, &pkt->esp, sizeof(pkt->esp) + crypt_len);
	if (err) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to calculate HMAC for ESP packet: %s\n"),
			     gnutls_strerror(err));
		return -EIO;
	}
	gnutls_hmac_output(vpninfo->esp_out.hmac, pkt->data + crypt_len);

	memcpy(vpninfo->esp_out.iv, pkt->data + crypt_len, blksize);
	gnutls_cipher_encrypt(vpninfo->esp_out.cipher, vpninfo->esp_out.iv, blksize);
	return 0;
}
