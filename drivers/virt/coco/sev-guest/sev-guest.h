/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * SEV-SNP API spec is available at https://developer.amd.com/sev
 */

#ifndef __VIRT_SEVGUEST_H__
#define __VIRT_SEVGUEST_H__

#include <linux/miscdevice.h>
#include <linux/types.h>

/* SNP Guest message request */
struct snp_req_data {
	unsigned long req_gpa;
	unsigned long resp_gpa;
	unsigned long data_gpa;
	unsigned int data_npages;
};

struct snp_guest_crypto {
	struct crypto_aead *tfm;
	u8 *iv, *authtag;
	int iv_len, a_len;
};

struct snp_guest_dev {
	struct device *dev;
	struct miscdevice misc;

	void *certs_data;
	struct snp_guest_crypto *crypto;
	/* request and response are in unencrypted memory */
	struct snp_guest_msg *request, *response;

	/*
	 * Avoid information leakage by double-buffering shared messages
	 * in fields that are in regular encrypted memory.
	 */
	struct snp_guest_msg secret_request, secret_response;

	struct snp_secrets_page_layout *layout;
	struct snp_req_data input;
	union {
		struct snp_report_req report;
		struct snp_derived_key_req derived_key;
		struct snp_ext_report_req ext_report;
	} req;
	u32 *os_area_msg_seqno;
	u8 *vmpck;
};

u64 snp_get_msg_seqno(struct snp_guest_dev *snp_dev);
int enc_payload(struct snp_guest_dev *snp_dev, u64 seqno, int version, u8 type,
		void *payload, size_t sz);
int verify_and_dec_payload(struct snp_guest_dev *snp_dev, void *payload, u32 sz);
void *alloc_shared_pages(struct device *dev, size_t sz);
void free_shared_pages(void *buf, size_t sz);

#endif /* __VIRT_SEVGUEST_H__ */
