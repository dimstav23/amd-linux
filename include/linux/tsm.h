/* SPDX-License-Identifier: GPL-2.0 */

#ifndef LINUX_TSM_H
#define LINUX_TSM_H

#include <linux/cdev.h>

/* SPDM control structure for DOE */
struct tsm_spdm {
	unsigned long req_len;
	void *req;
	unsigned long rsp_len;
	void *rsp;

	struct pci_doe_mb *doe_mb;
	struct pci_doe_mb *doe_mb_secured;
	int (*cb)(struct tsm_spdm *spdm, bool secured);
};

/* Data object for measurements/certificates/attestationreport */
struct tsm_blob {
	void *data;
	u32 len;
	struct kref kref;
	void (*release)(struct tsm_blob *b);
};

struct tsm_blob *tsm_blob_new(void *data, u32 len, void (*release)(struct tsm_blob *b));
struct tsm_blob *tsm_blob_get(struct tsm_blob *b);
void tsm_blob_put(struct tsm_blob *b);

/**
 * struct tdisp_interface_id - TDISP INTERFACE_ID Definition
 *
 * @function_id: Identifies the function of the device hosting the TDI
 * 15:0: @rid: Requester ID
 * 23:16: @rseg: Requester Segment (Reserved if Requester Segment Valid is Clear)
 * 24: @rseg_valid: Requester Segment Valid
 * 31:25 – Reserved
 * 8B - Reserved
*/
struct tdisp_interface_id {
	union {
		struct {
			u32 function_id;
			u8 reserved[8];
		};
		struct {
			u16 rid;
			u8 rseg;
			u8 rseg_valid : 1;
		};
	};
};

/* Physical device descriptor responsible for IDE/TDISP setup */
struct tsm_dev {
	const struct attribute_group *ag;
	struct pci_dev *pdev; /* Physical PCI function #0 */
	struct tsm_spdm spdm;

	u8 tc_count;
	u8 cert_slot;
	u8 connected;

	struct tsm_blob *meas;
	struct tsm_blob *certs;

	void *data; /* Platform specific data */
};

/* PCI function for passing through, can be the same as tsm_dev::pdev */
struct tsm_tdi {
	const struct attribute_group *ag;
	struct pci_dev *pdev;
	struct tsm_dev *tdev;

	u8 rseg;
	u8 rseg_valid;
	bool validated;

	int bindfd;

	struct tsm_blob *report;

	void *data; /* Platform specific data */
};

struct tsm_tdi_binding {
	struct tsm_tdi *tdi;
	u64 vmid;
	u16 guest_rid;
};

struct tsm_dev_status {
	u8 ctx_state;
	u8 tc_mask;
	u8 certs_slot;
	u16 device_id;
	u16 segment_id;
	u8 no_fw_update;
};

enum tsm_spdm_algos {
	TSM_TDI_SPDM_ALGOS_DHE_SECP256R1,
	TSM_TDI_SPDM_ALGOS_DHE_SECP384R1,
	TSM_TDI_SPDM_ALGOS_AEAD_AES_128_GCM,
	TSM_TDI_SPDM_ALGOS_AEAD_AES_256_GCM,
	TSM_TDI_SPDM_ALGOS_ASYM_TPM_ALG_RSASSA_3072,
	TSM_TDI_SPDM_ALGOS_ASYM_TPM_ALG_ECDSA_ECC_NIST_P256,
	TSM_TDI_SPDM_ALGOS_ASYM_TPM_ALG_ECDSA_ECC_NIST_P384,
	TSM_TDI_SPDM_ALGOS_HASH_TPM_ALG_SHA_256,
	TSM_TDI_SPDM_ALGOS_HASH_TPM_ALG_SHA_384,
	TSM_TDI_SPDM_ALGOS_KEY_SCHED_SPDM_KEY_SCHEDULE,
};

enum tsm_tdisp_state {
	TDISP_STATE_CONFIG_UNLOCKED,
	TDISP_STATE_CONFIG_LOCKED,
	TDISP_STATE_RUN,
	TDISP_STATE_ERROR
};

struct tsm_tdi_status {
	u8 meas_digest_fresh:1;
	u8 meas_digest_valid:1;
	u8 all_request_redirect:1;
	u8 bind_p2p:1;
	u8 lock_msix:1;
	u8 no_fw_update:1;
	u16 cache_line_size;
	u64 spdm_algos; /* Bitmask of (1<<TSM_TDI_SPDM_ALGOS_xxx) */
	u8 certs_digest[48];
	u8 meas_digest[48];
	u8 interface_report_digest[48];

	/* HV only */
	struct tdisp_interface_id id;
	u8 guest_report_id[16];
	enum tsm_tdisp_state state;
};

struct tsm_ops {
	/* HV hooks */
	int (*dev_connect)(struct tsm_dev *tdev, void *private_data);
	void (*dev_reclaim)(struct tsm_dev *tdev, void *private_data);
	int (*dev_status)(struct tsm_dev *tdev, void *private_data, struct tsm_dev_status *s);
	int (*tdi_bind)(struct tsm_tdi *tdi, u32 bdfn, u64 kvmid, void *private_data);
	void (*tdi_reclaim)(struct tsm_tdi *tdi, void *private_data);

	int (*guest_request)(struct tsm_tdi *tdi, u32 guest_rid, u64 kvmid, void *req_data,
			     struct file *vfile, void *private_data);

	/* VM hooks */
	int (*tdi_validate)(struct tsm_tdi *tdi, bool invalidate, void *private_data);

	/* HV and VM hooks */
	int (*tdi_status)(struct tsm_tdi *tdi, void *private_data, struct tsm_tdi_status *ts);
};

void tsm_set_ops(struct tsm_ops *ops, void *private_data);
struct tsm_tdi *tsm_tdi_get(struct device *dev);
struct tsm_dev *tsm_dev_get(struct device *dev);
int tsm_tdi_bind(struct tsm_tdi *tdi, u32 guest_rid, u64 kvmid);
int tsm_guest_request(int fd, void *req_data, struct file *vfile);
int tsm_tdi_find(u32 guest_rid, u64 kvmid);
struct tsm_tdi *tsm_bindfd_to_tdi(int bindfd);

#endif /* LINUX_TSM_H */
