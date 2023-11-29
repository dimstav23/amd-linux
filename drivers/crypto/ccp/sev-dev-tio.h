#ifndef __PSP_SEV_TIO_H__
#define __PSP_SEV_TIO_H__

#include <linux/tsm.h>
#include <uapi/linux/psp-sev.h>

#if defined(CONFIG_CRYPTO_DEV_SP_PSP) || defined(CONFIG_CRYPTO_DEV_SP_PSP_MODULE)

int sev_tio_cmd_buffer_len(int cmd);

typedef union {
	u64 sla;
	struct {
		u64 page_type : 1;
		u64 page_size : 1;
		u64 reserved1 : 10;
		u64 pfn : 40;
		u64 reserved2 : 12;
	};
} __packed sla_addr_t;

/* struct tsm_dev::data */
struct tsm_dev_tio {
	sla_addr_t dev_ctx;
	sla_addr_t req; // Points to spdm_buf_hdr
	sla_addr_t resp; // Points to spdm_buf_hdr
	sla_addr_t scratch; // Points to spdm_buf_hdr
	size_t dev_ctx_len;
	size_t scratch_len;
};

/* struct tsm_tdi::data */
struct tsm_tdi_tio {
	sla_addr_t tdi_ctx;
	u64 gctx_paddr;
	size_t tdi_ctx_len;
};

int sev_tio_dev_measurements(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm, struct tsm_blob **meas);
int sev_tio_dev_create(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm);
int sev_tio_dev_connect(struct tsm_dev_tio *dev_data, u16 device_id, u16 root_port_id, u8 segment_id,
			u8 tc_mask, u8 cert_slot, struct tsm_spdm *spdm, struct tsm_blob **certs);
void sev_tio_dev_disconnect(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm);
void sev_tio_dev_reclaim(struct tsm_dev_tio *dev_data);
int sev_tio_dev_status(struct tsm_dev_tio *dev_data, struct tsm_dev_status *status);

int sev_tio_tdi_create(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, u16 dev_id,
		       u8 rseg, u8 rseg_valid);
void sev_tio_tdi_reclaim(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data);
int sev_tio_guest_request(void *data, int *fw_err, u32 guest_rid, u64 gctx_paddr,
			  struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm);

int sev_tio_tdi_bind(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, __u32 guest_rid, u64 gctx_paddr,
		struct tsm_spdm *spdm, struct tsm_blob **report);
void sev_tio_tdi_unbind(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, struct tsm_spdm *spdm);

int sev_tio_tdi_info(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, struct tsm_tdi_status *ts);
int sev_tio_tdi_status(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, struct tsm_tdi_status *ts,
		       struct tsm_spdm *spdm);

#endif	/* CONFIG_CRYPTO_DEV_SP_PSP */

#endif	/* __PSP_SEV_TIO_H__ */
