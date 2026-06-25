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

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#define EVP_CIPHER_CTX_free(c) do {				\
				    EVP_CIPHER_CTX_cleanup(c);	\
				    free(c); } while (0)
#define HMAC_CTX_free(c) do {					\
				    HMAC_CTX_cleanup(c);	\
				    free(c); } while (0)

static inline HMAC_CTX *HMAC_CTX_new(void)
{
	HMAC_CTX *ret = malloc(sizeof(*ret));
	if (ret)
		HMAC_CTX_init(ret);
	return ret;
}
#endif

void destroy_esp_ciphers(struct esp *esp)
{
	if (esp->cipher) {
		EVP_CIPHER_CTX_free(esp->cipher);
		esp->cipher = NULL;
	}
	if (esp->hmac) {
		HMAC_CTX_free(esp->hmac);
		esp->hmac = NULL;
	}
}

static const EVP_CIPHER *esp_gcm_cipher(const struct openconnect_info *vpninfo)
{
	return vpninfo->esp_enc == ENC_AES_256_GCM ?
		EVP_aes_256_gcm() : EVP_aes_128_gcm();
}

static void esp_gcm_nonce(unsigned char *nonce, const unsigned char *iv, uint32_t seq)
{
	memcpy(nonce, iv, ESP_GCM_IV_LEN);
	memcpy(nonce + ESP_GCM_IV_LEN, &seq, 4);
}

static int esp_gcm_init(struct openconnect_info *vpninfo, EVP_CIPHER_CTX *ctx,
			const unsigned char *key, const unsigned char *iv, uint32_t seq,
			int enc)
{
	unsigned char nonce[12];

	esp_gcm_nonce(nonce, iv, seq);
	if (!EVP_CipherInit_ex(ctx, esp_gcm_cipher(vpninfo), NULL, key, nonce, enc))
		return -EIO;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(nonce), NULL))
		return -EIO;
	return 0;
}

static int esp_gcm_aad(struct openconnect_info *vpninfo, EVP_CIPHER_CTX *ctx,
		       const struct pkt *pkt)
{
	unsigned char aad[8];
	int aadlen = 0;

	memcpy(aad, &pkt->esp.spi, 8);
	if (!EVP_CipherUpdate(ctx, NULL, &aadlen, aad, sizeof(aad))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set ESP GCM AAD\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EIO;
	}
	return 0;
}

static int init_esp_cipher(struct openconnect_info *vpninfo, struct esp *esp,
			    const EVP_MD *macalg, const EVP_CIPHER *encalg, int decrypt,
			    int gcm)
{
	int ret;

	destroy_esp_ciphers(esp);

	if (gcm)
		return 0;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	esp->cipher = malloc(sizeof(*esp->cipher));
	if (!esp->cipher)
		return -ENOMEM;
	EVP_CIPHER_CTX_init(esp->cipher);
#else
	esp->cipher = EVP_CIPHER_CTX_new();
	if (!esp->cipher)
		return -ENOMEM;
#endif

	if (decrypt)
		ret = EVP_DecryptInit_ex(esp->cipher, encalg, NULL, esp->enc_key, NULL);
	else {
		ret = EVP_EncryptInit_ex(esp->cipher, encalg, NULL, esp->enc_key, esp->iv);
	}

	if (!ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialise ESP cipher:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EIO;
	}
	EVP_CIPHER_CTX_set_padding(esp->cipher, 0);

	esp->hmac = HMAC_CTX_new();
	if (!esp->hmac) {
		destroy_esp_ciphers(esp);
		return -ENOMEM;
	}
	if (!HMAC_Init_ex(esp->hmac, esp->hmac_key,
			  EVP_MD_size(macalg), macalg, NULL)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to initialize ESP HMAC\n"));

		openconnect_report_ssl_errors(vpninfo);
		destroy_esp_ciphers(esp);
	}

	return 0;
}

int init_esp_ciphers(struct openconnect_info *vpninfo, struct esp *esp_out, struct esp *esp_in)
{
	const EVP_CIPHER *encalg;
	const EVP_MD *macalg = NULL;
	int gcm = esp_uses_gcm(vpninfo);
	int ret;

	switch (vpninfo->esp_enc) {
	case ENC_AES_128_CBC:
		encalg = EVP_aes_128_cbc();
		break;
	case ENC_AES_256_CBC:
		encalg = EVP_aes_256_cbc();
		break;
	case ENC_AES_128_GCM:
	case ENC_AES_256_GCM:
		encalg = esp_gcm_cipher(vpninfo);
		break;
	default:
		return -EINVAL;
	}

	if (!gcm) {
		switch (vpninfo->esp_hmac) {
		case HMAC_MD5:
			macalg = EVP_md5();
			break;
		case HMAC_SHA1:
			macalg = EVP_sha1();
			break;
		case HMAC_SHA256:
			macalg = EVP_sha256();
			break;
		default:
			return -EINVAL;
		}
	}

	ret = init_esp_cipher(vpninfo, &vpninfo->esp_out, macalg, encalg, 0, gcm);
	if (ret)
		return ret;

	ret = init_esp_cipher(vpninfo, esp_in, macalg, encalg, 1, gcm);
	if (ret) {
		destroy_esp_ciphers(&vpninfo->esp_out);
		return ret;
	}

	return 0;
}

/* pkt->len shall be the *payload* length. Omitting the header and the ICV/HMAC */
int decrypt_esp_packet(struct openconnect_info *vpninfo, struct esp *esp, struct pkt *pkt)
{
	unsigned char hmac_buf[MAX_HMAC_SIZE];
	unsigned int hmac_len = sizeof(hmac_buf);
	int crypt_len = pkt->len;
	EVP_CIPHER_CTX *ctx;

	if (verify_packet_seqno(vpninfo, esp, ntohl(pkt->esp.seq)))
		return -EINVAL;

	if (esp_uses_gcm(vpninfo)) {
		int outlen = 0;

		if (pkt->len < vpninfo->hmac_out_len)
			return -EINVAL;

		ctx = EVP_CIPHER_CTX_new();
		if (!ctx)
			return -ENOMEM;

		if (esp_gcm_init(vpninfo, ctx, esp->enc_key, pkt->esp.iv, pkt->esp.seq, 0) < 0 ||
		    esp_gcm_aad(vpninfo, ctx, pkt) < 0) {
			EVP_CIPHER_CTX_free(ctx);
			return -EINVAL;
		}

		pkt->len -= vpninfo->hmac_out_len;
		memcpy(hmac_buf, pkt->data + pkt->len, vpninfo->hmac_out_len);
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, vpninfo->hmac_out_len,
					 hmac_buf) ||
		    !EVP_DecryptUpdate(ctx, pkt->data, &outlen, pkt->data, pkt->len) ||
		    !EVP_DecryptFinal_ex(ctx, pkt->data + outlen, &outlen)) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received ESP GCM packet with invalid ICV\n"));
			EVP_CIPHER_CTX_free(ctx);
			return -EINVAL;
		}

		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	HMAC_Init_ex(esp->hmac, NULL, 0, NULL, NULL);
	HMAC_Update(esp->hmac, (void *)&pkt->esp, sizeof(pkt->esp) + pkt->len);
	HMAC_Final(esp->hmac, hmac_buf, &hmac_len);

	if (memcmp(hmac_buf, pkt->data + pkt->len, vpninfo->hmac_out_len)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received ESP packet with invalid HMAC\n"));
		return -EINVAL;
	}

	if (!EVP_DecryptInit_ex(esp->cipher, NULL, NULL, NULL,
				pkt->esp.iv)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set up decryption context for ESP packet:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	if (!EVP_DecryptUpdate(esp->cipher, pkt->data, &crypt_len,
			       pkt->data, pkt->len)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to decrypt ESP packet:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	return 0;
}

int encrypt_esp_packet(struct openconnect_info *vpninfo, struct pkt *pkt, int crypt_len)
{
	int blksize = 16;
	unsigned int hmac_len = vpninfo->hmac_out_len;
	EVP_CIPHER_CTX *ctx;
	int outlen = 0;

	if (esp_uses_gcm(vpninfo)) {
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx)
			return -ENOMEM;

		if (esp_gcm_init(vpninfo, ctx, vpninfo->esp_out.enc_key,
				 pkt->esp.iv, pkt->esp.seq, 1) < 0 ||
		    esp_gcm_aad(vpninfo, ctx, pkt) < 0 ||
		    !EVP_EncryptUpdate(ctx, pkt->data, &outlen, pkt->data, crypt_len) ||
		    !EVP_EncryptFinal_ex(ctx, pkt->data + outlen, &outlen) ||
		    !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, vpninfo->hmac_out_len,
					 pkt->data + crypt_len)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to encrypt ESP GCM packet:\n"));
			openconnect_report_ssl_errors(vpninfo);
			EVP_CIPHER_CTX_free(ctx);
			return -EINVAL;
		}

		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	if (!EVP_EncryptUpdate(vpninfo->esp_out.cipher, pkt->data, &crypt_len,
			       pkt->data, crypt_len)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to encrypt ESP packet:\n"));
		openconnect_report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	HMAC_Init_ex(vpninfo->esp_out.hmac, NULL, 0, NULL, NULL);
	HMAC_Update(vpninfo->esp_out.hmac, (void *)&pkt->esp, sizeof(pkt->esp) + crypt_len);
	HMAC_Final(vpninfo->esp_out.hmac, pkt->data + crypt_len, &hmac_len);

	EVP_EncryptUpdate(vpninfo->esp_out.cipher, vpninfo->esp_out.iv, &blksize,
			  pkt->data + crypt_len + hmac_len - blksize, blksize);
	return 0;
}