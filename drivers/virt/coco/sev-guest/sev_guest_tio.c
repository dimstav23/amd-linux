// SPDX-License-Identifier: GPL-2.0-only

#include <linux/pci.h>
#include <linux/psp-sev.h>
#include <linux/tsm.h>

#include <asm/svm.h>
#include <asm/sev.h>

#include "sev-guest.h"

#define TIO_MESSAGE_VERSION	1

static void tio_guest_blob_free(struct tsm_blob *b)
{
	kvfree(b->data);
}

static struct tsm_blob *tio_guest_blob(u8 *src, size_t len, u8 digest[48])
{
	struct tsm_blob *b;
	void *data = vmalloc(len);
	if (!data)
		return NULL;

	// VERIFY digest vs the blob

	memcpy(data, src, len);

	b = tsm_blob_new(data, len, tio_guest_blob_free);
	return b;
}

static int handle_guest_request_tio(u64 bdfn, struct snp_guest_dev *snp_dev,
				    u8 type, void *req_buf, size_t req_sz, void *resp_buf,
				    u32 resp_sz, u64 rmp_range, __u64 *fw_err,
				    u64 pages, u64 *bytes)
{
	u64 seqno, err;
	int rc;

	/* Get message sequence and verify that its a non-zero */
	seqno = snp_get_msg_seqno(snp_dev);
	if (!seqno)
		return -EIO;

	memset(snp_dev->response, 0, sizeof(struct snp_guest_msg));

	/* Encrypt the userspace provided payload */
	rc = snp_issue_guest_request(SVM_VMGEXIT_SEV_TIO_GUEST_REQUEST,
				     snp_dev->input.req_gpa, snp_dev->input.resp_gpa,
				     &pages, bytes, &bdfn, rmp_range ? &rmp_range : NULL, &err);
	if (fw_err)
		*fw_err = err;

	if (rc)
		return rc;

	rc = verify_and_dec_payload(snp_dev, resp_buf, resp_sz);
	if (rc)
		return rc;

	return 0;
}

struct tio_msg_tdi_info_req {
	__u32 length;
	__u16 guest_device_id;
	__u8 reserved[10];
};

struct tio_msg_tdi_info_rsp {
	__u32 length;
	__u16 status;
	__u16 guest_device_id;
	__u64 reserved1;
	union {
		u32 meas_flags;
		struct {
			u32 meas_digest_valid : 1;
			u32 meas_digest_fresh : 1;
		};
	};
	union {
		u16 tdisp_lock_flags;
		// These are TDISP's LOCK_INTERFACE_REQUEST flags
		struct {
			u16 no_fw_update : 1;
			u16 cache_line_size : 1;
			u16 lock_msix : 1;
			u16 bind_p2p : 1;
			u16 all_request_redirect : 1;
		};
	};
	__u16 reserved2;
	__u64 spdm_algos;
	__u8 certs_digest[48];
	__u8 meas_digest[48];
	__u8 interface_report_digest[48];
};

#define TIO_SPDM_ALGOS_DHE_SECP256R1 			0
#define TIO_SPDM_ALGOS_DHE_SECP384R1 			1
#define TIO_SPDM_ALGOS_AEAD_AES_128_GCM 		(0<<8)
#define TIO_SPDM_ALGOS_AEAD_AES_256_GCM			(1<<8)
#define TIO_SPDM_ALGOS_ASYM_TPM_ALG_RSASSA_3072		(0<<16)
#define TIO_SPDM_ALGOS_ASYM_TPM_ALG_ECDSA_ECC_NIST_P256	(1<<16)
#define TIO_SPDM_ALGOS_ASYM_TPM_ALG_ECDSA_ECC_NIST_P384	(2<<16)
#define TIO_SPDM_ALGOS_HASH_TPM_ALG_SHA_256		(0<<24)
#define TIO_SPDM_ALGOS_HASH_TPM_ALG_SHA_384		(1<<24)
#define TIO_SPDM_ALGOS_KEY_SCHED_SPDM_KEY_SCHEDULE	(0ULL<<32)

static int sev_guest_tdi_status(struct tsm_tdi *tdi, void *private_data, struct tsm_tdi_status *ts)
{
	struct snp_guest_dev *snp_dev = private_data;
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	size_t resp_len = sizeof(struct tio_msg_tdi_info_rsp) + crypto->a_len;
	struct tio_msg_tdi_info_rsp *rsp = kmalloc(resp_len, GFP_KERNEL);
	struct tio_msg_tdi_info_req req = {
		.length = sizeof(req),
		.guest_device_id = pci_dev_id(tdi->pdev),
	};
	u64 fw_err = 0, certs_size = SZ_32K;
	struct tio_blob_table_entry *pt;
	int rc;

	if (!rsp)
		return -ENOMEM;

	rsp->length = sizeof(*rsp);

	pt = alloc_shared_pages(snp_dev->dev, certs_size);
	if (!pt)
		return -ENOMEM;

	rc = handle_guest_request_tio(pci_dev_id(tdi->pdev), snp_dev,
				      TIO_MSG_TDI_INFO_REQ,
				      &req, sizeof(req), rsp, resp_len, 0, &fw_err,
				      __pa(pt), &certs_size);
	if (certs_size > SZ_32K) {
		free_shared_pages(pt, certs_size);
		pt = alloc_shared_pages(snp_dev->dev, certs_size);
		if (!pt)
			return -ENOMEM;

		rc = handle_guest_request_tio(pci_dev_id(tdi->pdev), snp_dev,
					      TIO_MSG_TDI_INFO_REQ,
					      &req, sizeof(req), rsp, resp_len, 0, &fw_err,
					      __pa(pt), &certs_size);
	}

	if (rc == 0) {
		tsm_blob_put(tdi->tdev->meas);
		tsm_blob_put(tdi->tdev->certs);
		tsm_blob_put(tdi->report);
		tdi->tdev->meas = NULL;
		tdi->tdev->certs = NULL;
		tdi->report = NULL;

		for (unsigned i = 0; i < 10; ++i) {
			u8 *ptr = ((u8 *) pt) + pt[i].offset;
			size_t len = pt[i].length;

			if (guid_equal(&pt[i].guid, &TIO_GUID_MEASUREMENTS))
				tdi->tdev->meas = tio_guest_blob(ptr, len, rsp->meas_digest);
			else if (guid_equal(&pt[i].guid, &TIO_GUID_CERTIFICATES))
				tdi->tdev->certs = tio_guest_blob(ptr, len, rsp->certs_digest);
			else if (guid_equal(&pt[i].guid, &TIO_GUID_REPORT))
				tdi->report = tio_guest_blob(ptr, len, rsp->interface_report_digest);
			else if (guid_is_null(&pt[i].guid))
				break;
		}

		ts->meas_digest_valid = rsp->meas_digest_valid;
		ts->meas_digest_fresh = rsp->meas_digest_fresh;
		ts->no_fw_update = rsp->no_fw_update;
		ts->cache_line_size = rsp->cache_line_size == 0 ? 64 : 128;
		ts->lock_msix = rsp->lock_msix;
		ts->bind_p2p = rsp->bind_p2p;
		ts->all_request_redirect = rsp->all_request_redirect;
#define __ALGO(x, n, y) ((((x) & (0xFFUL << (n))) == TIO_SPDM_ALGOS_##y) ? (1ULL << TSM_TDI_SPDM_ALGOS_##y) : 0)
		ts->spdm_algos =
			__ALGO(rsp->spdm_algos, 0, DHE_SECP256R1) |
			__ALGO(rsp->spdm_algos, 0, DHE_SECP384R1) |
			__ALGO(rsp->spdm_algos, 8, AEAD_AES_128_GCM) |
			__ALGO(rsp->spdm_algos, 8, AEAD_AES_256_GCM) |
			__ALGO(rsp->spdm_algos, 16, ASYM_TPM_ALG_RSASSA_3072) |
			__ALGO(rsp->spdm_algos, 16, ASYM_TPM_ALG_ECDSA_ECC_NIST_P256) |
			__ALGO(rsp->spdm_algos, 16, ASYM_TPM_ALG_ECDSA_ECC_NIST_P384) |
			__ALGO(rsp->spdm_algos, 24, HASH_TPM_ALG_SHA_256) |
			__ALGO(rsp->spdm_algos, 24, HASH_TPM_ALG_SHA_384) |
			__ALGO(rsp->spdm_algos, 32, KEY_SCHED_SPDM_KEY_SCHEDULE);
#undef __ALGO
		memcpy(ts->certs_digest, rsp->certs_digest, sizeof(ts->certs_digest));
		memcpy(ts->meas_digest, rsp->meas_digest, sizeof(ts->meas_digest));
		memcpy(ts->interface_report_digest, rsp->interface_report_digest,
		       sizeof(ts->interface_report_digest));
	}
	free_shared_pages(pt, certs_size);

	/* The response buffer contains the sensitive data, explicitly clear it. */
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

struct tio_msg_mmio_validate_req {
	__u32 length; // Length of this structure in bytes.
	__u16 guest_device_id; // Hypervisor provided identifier used by the guest to identify
			// the TDI in guest messages.
	__u8 reserved1[10];
	__u64 base; // Guest physical address of the subrange.
	__u32 range_length; // Length of the subrange in bytes.
	__u32 range_offset; // Offset of the subrange within the MMIO range.
	union {
		__u16 flags;
		struct {
			__u16 validated:1; // Desired value to set RMP.Validated for the range.
			// Force validated:
			// 0: If subrange does not have RMP.Validated set uniformly, fail.
			// 1: If subrange does not have RMP.Validated set uniformly, force
			// 	to requested value.
			__u16 force_validated:1;
		};
	};
	__u16 range_id; // RangeID of MMIO range.
	__u32 reserved2;
};

#define MMIO_VALIDATE_SUCCESS 0
#define MMIO_VALIDATE_TDI_NOT_BOUND 1 // The TDI is not bound or unknown.
#define MMIO_VALIDATE_NOT_ASSIGNED 2 // At least one page is not assigned to the guest.
#define MMIO_VALIDATE_NOT_MAPPED 3 // At least one page is not mapped to the expected GPA.
#define MMIO_VALIDATE_NOT_VALIDATED 4 // The Validated bit is not uniformly set for the MMIO range.
#define MMIO_VALIDATE_NOT_IO 5 // At least one page is not an I/O page.
#define MMIO_VALIDATE_NOT_REPORTED 6 // The provided MMIO range ID is not reported in the interface report.

static const char *mmio_fw_err_to_str(u64 fw_err)
{
	switch (fw_err & 0xFFFFFFFF) {
#define __FWERR(x)	case MMIO_VALIDATE_##x: return #x
	__FWERR(SUCCESS);
	__FWERR(TDI_NOT_BOUND);
	__FWERR(NOT_ASSIGNED);
	__FWERR(NOT_VALIDATED);
	__FWERR(NOT_IO);
	__FWERR(NOT_REPORTED);
#undef __FWERR
	}
	return "unknown";
}

struct tio_msg_mmio_validate_rsp {
	__u32 length; // Length of this structure in bytes.
	__u32 status; // MMIO_VALIDATE_xxx
	__u64 guest_interface_id;
	__u64 base; // Guest physical address of the subrange.
	__u32 range_length; // Length of the subrange in bytes.
	__u32 range_offset; // Offset of the subrange within the MMIO range.
	union {
		__u16 flags;
		struct {
			__u16 changed:1; // Indicates that the Validated bit has changed
					// due to this operation.
		};
	};
	__u16 range_id; // RangeID of MMIO range.
	__u32 reserved;
};

static int mmio_validate_range(struct tsm_tdi *tdi, struct snp_guest_dev *snp_dev,
			       struct pci_dev *pdev,
			       unsigned int range_id, resource_size_t start, resource_size_t size,
			       u64 *fw_err)
{
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	size_t resp_len = sizeof(struct tio_msg_mmio_validate_rsp) + crypto->a_len;
	struct tio_msg_mmio_validate_rsp *rsp = kmalloc(resp_len, GFP_KERNEL);
	struct tio_msg_mmio_validate_req req = {
		.length = sizeof(req),
		.guest_device_id = pci_dev_id(tdi->pdev),
		.base = start, // Guest physical address of the subrange.
		.range_length = size, // Length of the subrange in bytes.
		.range_offset = 0, // Offset of the subrange within the MMIO range.
		.validated = 1, // Desired value to set RMP.Validated for the range.
		.force_validated = 0,
		.range_id = range_id, // RangeID of MMIO range.
	};
	int rc;

	if (!rsp)
		return -ENOMEM;

	rsp->length = sizeof(*rsp);
	rc = handle_guest_request_tio(pci_dev_id(tdi->pdev), snp_dev, TIO_MSG_MMIO_VALIDATE_REQ,
				      &req, sizeof(req), rsp, resp_len,
				      MMIO_MK_VALIDATE(start, size, range_id),
				      fw_err, 0, NULL);
	if (rc)
		goto free_exit;

free_exit:
	/* The response buffer contains the sensitive data, explicitly clear it. */
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

static int tio_tdi_mmio_validate(struct tsm_tdi *tdi, struct snp_guest_dev *snp_dev)
{
	struct pci_dev *pdev = tdi->pdev;
	u64 fw_err = 0;
	int i = 0, rc;
	struct resource *r;

	// FIXME: verify what the range id really is in TDISP
	pci_dev_for_each_resource(pdev, r) {
		rc = mmio_validate_range(tdi, snp_dev, pdev, i, r->start, r->end - r->start + 1, &fw_err);
		if (rc) {
			pr_err("MMIO #%d %llx..%llx failed with 0x%llx %s\n",
				i, r->start, r->end, fw_err, mmio_fw_err_to_str(fw_err));
			break;
		}
		++i;
	}

	return rc;
}

// 512 bit long struct, DOUBLE CHECK
struct sdte {
	__u8 v:1; // TDI is allowed to access guest private memory and this SDTE is valid.
	__u8 reserved10:7;
	__u8 reserved11[29]; // 240:1 Reserved
	__u8 reserved12:1;
	__u8 vmpl:2; // 242:241 VMPL applied to all accesses by this TDI.
	__u8 reserved20:5;
	__u8 reserved21[9]; // 319:243 Reserved
	__u32 vtom_enabled:1; // 320 vTOM enabled
	__u32 virtual_tom:31; // 351:321 vTOM applied to all TDI accesses.
	__u8 reserved6[20]; // 511:350 Reserved
};

struct tio_msg_sdte_write_req {
	__u32 length; // Length of this structure in bytes.
	__u16 guest_device_id; // Hypervisor provided identifier used by the guest to identify the TDI in guest messages.
	__u64 guest_interface_id; // ???
	struct sdte sdte;
};

#define SDTE_WRITE_SUCCESS 0
#define SDTE_WRITE_TDI_NOT_BOUND 1 // The TDI is not bound or unknown.
#define SDTE_WRITE_RESERVED 2 // Reserved fields were not 0
#define SDTE_WRITE_INVALID 3 // A provided field has an invalid value
#define SDTE_WRITE_NO_INFO_REQ 4 // The guest has not sent TIO_MSG_TDI_INFO_REQ since the last TIO_TDI_BIND command was invoked

static const char *sdte_fw_err_to_str(u64 fw_err)
{
	switch (fw_err & 0xFFFFFFFF) {
#define __FWERR(x)	case SDTE_WRITE_##x: return #x
	__FWERR(SUCCESS);
	__FWERR(TDI_NOT_BOUND);
	__FWERR(RESERVED);
	__FWERR(INVALID);
	__FWERR(NO_INFO_REQ);
#undef __FWERR
	}
	return "unknown";
}

struct tio_msg_sdte_write_rsp {
	__u32 length; // Length of this structure in bytes.
	__u32 status; // SDTE_WRITE_xxx
};

static int tio_tdi_sdte_write(struct tsm_tdi *tdi, struct snp_guest_dev *snp_dev)
{
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	size_t resp_len = sizeof(struct tio_msg_tdi_info_rsp) + crypto->a_len;
	struct tio_msg_sdte_write_rsp *rsp = kmalloc(resp_len, GFP_KERNEL);
	struct tio_msg_sdte_write_req req = {
		.length = sizeof(req),
		.guest_device_id = pci_dev_id(tdi->pdev),
		.sdte.vmpl = 0, // VMPL other than 0 require SVSM call
		.sdte.virtual_tom = 0, // 0 == all encrypted?
		.sdte.vtom_enabled = 1, // no vIOMMU support yet
		.sdte.v = 1, // valid
	};
	u64 fw_err = 0;
	int rc;

	BUILD_BUG_ON(sizeof(struct sdte) * 8 != 512);

	if (!rsp)
		return -ENOMEM;

	rsp->length = sizeof(*rsp);
	rc = handle_guest_request_tio(pci_dev_id(tdi->pdev), snp_dev, TIO_MSG_SDTE_WRITE_REQ,
				      &req, sizeof(req), rsp, resp_len, 0, &fw_err, 0, NULL);
	if (rc) {
		pr_err("SDTE write failed with 0x%llx %s\n", fw_err, sdte_fw_err_to_str(fw_err));
		goto free_exit;
	}

free_exit:
	/* The response buffer contains the sensitive data, explicitly clear it. */
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

static int sev_guest_tdi_validate(struct tsm_tdi *tdi, bool invalidate, void *private_data)
{
	struct snp_guest_dev *snp_dev = private_data;
	int ret;

	if (!tdi->report)
		return -EPERM;

	//
	// Now we should have certs/meas/attestation report
	//
	// This expects tsm.ko to be loaded before the device driver.
	//

	ret = tio_tdi_mmio_validate(tdi, snp_dev);
	if (ret)
		return ret;

	ret = tio_tdi_sdte_write(tdi, snp_dev);
	if (ret)
		return ret;

	return 0;
}

struct tsm_ops sev_guest_tsm_ops = {
	.tdi_validate = sev_guest_tdi_validate,
	.tdi_status = sev_guest_tdi_status,
};

void sev_guest_tsm_set_ops(bool set, struct snp_guest_dev *snp_dev)
{
	if (set)
		tsm_set_ops(&sev_guest_tsm_ops, snp_dev);
	else
		tsm_set_ops(NULL, NULL);
}
