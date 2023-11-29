// SPDX-License-Identifier: GPL-2.0-only

// Interface to PSP for CCP/SEV-TIO/SNP-VM

#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/tsm.h>
#include <linux/psp.h>
#include <linux/file.h>

#include <asm/smp.h>
#include <asm/sev-common.h>
#include <asm/sev-host.h>

#include "psp-dev.h"
#include "sev-dev.h"
#include "sev-dev-tio.h"

#define SLA_PAGE_TYPE_DATA	0
#define SLA_PAGE_TYPE_SCATTER	1
#define SLA_PAGE_SIZE_4K	0
#define SLA_PAGE_SIZE_2M	1
#define SLA_EOL			0xFFFFFFFFFFUL
#define SLA_NULL		((sla_addr_t) { 0 })
#define IS_SLA_NULL(s)		((s).sla == SLA_NULL.sla)

#define __psp_pfn(x) (x) = __psp_pa((x) << PAGE_SHIFT) >> PAGE_SHIFT

// the BUFFER Structure
struct sla_buffer_hdr {
	u32 capacity; // The capacity of the buffer in bytes.
	u32 size; // The size of BUFFER_PAYLOAD in bytes. Must be multiple of 32B. (TODO: does is include this header?)
	u32 flags; //  Bit 0: Indicates that this buffer is encrypted. Bit[31:1]: Reserved.
	u32 reserved1; // 31:0 – Reserved.
	u8 iv[16]; //  IV used for the encryption of this buffer.
	u8 authtag[16]; // Authentication tag for this buffer.
	u8 reserved2[16];
	// 40h – BUFFER_PAYLOAD BUFFER_SIZE bytes of data.
} __packed;

#define SPDM_DOBJ_ID_NONE		0
#define SPDM_DOBJ_ID_REQ		1
#define SPDM_DOBJ_ID_RESP		2
/* SPDM_DOBJ_ID_SCRATCH			3  Cannot access this one at any time */
#define SPDM_DOBJ_ID_CERTIFICATE	4
#define SPDM_DOBJ_ID_MEASUREMENT	5
#define SPDM_DOBJ_ID_REPORT		6

struct spdm_dobj_hdr {
	u32 id;// 0h 31:0 DOBJ_ID Data object type identifier.
	u32 length;// Length of the data object in bytes, INCLUDING THIS HEADER. Must be a multiple of 32B.
	union {
		u16 ver;
		struct { //  8h 15:0 DOBJ_VERSION Version of the data object structure.
			u8 minor; // Bit[7:0]: Minor version.
			u8 major; // Bit[15:8]: Major versionthe DATA_OBJECT_HEADER Structure
		} version;
	};
} __packed;

struct spdm_dobj_hdr_req {
	struct spdm_dobj_hdr hdr; // id == SPDM_DOBJ_ID_REQ
	u8 spdm_type : 1; // 1: The packet is secured.
	u8 reserved1 : 7;
	u8 reserved2[5];
} __packed;

struct spdm_dobj_hdr_resp {
	struct spdm_dobj_hdr hdr; // id == SPDM_DOBJ_ID_RESP
	u8 spdm_type : 1; // 1: The packet is secured.
	u8 reserved1 : 7;
	u8 reserved2[5];
} __packed;

struct spdm_dobj_hdr_cert {
	struct spdm_dobj_hdr hdr; // id == SPDM_DOBJ_ID_CERTIFICATE
	u8 reserved1[6];
	u16 device_id;
	u8 segment_id;
	u8 type; // 1h: SPDM certificate. 0h, 2h–FFh: Reserved.
	u8 reserved2[12];
} __packed;

struct spdm_dobj_hdr_meas {
	struct spdm_dobj_hdr hdr; // id == SPDM_DOBJ_ID_MEASUREMENT
	u8 reserved1[6];
	u16 device_id;
	u8 segment_id;
	u8 type; // 1h: SPDM measurement. 0h, 2h–FFh: Reserved.
	u8 reserved2[12];
} __packed;

struct spdm_dobj_hdr_report {
	struct spdm_dobj_hdr hdr; // id == SPDM_DOBJ_ID_REPORT
	u8 reserved1[6];
	u16 device_id;
	u8 segment_id;
	u8 type; // 1h: TDISP interface report. 0h, 2h–FFh: Reserved.
	u8 reserved2[12];
} __packed;

struct spdm_ctrl {
	sla_addr_t req;
	sla_addr_t resp;
	sla_addr_t scratch;
	sla_addr_t output;
} __packed;

static size_t sla_dobj_id_to_size(u8 id)
{
	size_t n;

	switch (id) {
	case SPDM_DOBJ_ID_REQ: n = sizeof(struct spdm_dobj_hdr_req); break;
	case SPDM_DOBJ_ID_RESP: n = sizeof(struct spdm_dobj_hdr_resp); break;
	case SPDM_DOBJ_ID_CERTIFICATE: n = sizeof(struct spdm_dobj_hdr_cert); break;
	case SPDM_DOBJ_ID_MEASUREMENT: n = sizeof(struct spdm_dobj_hdr_meas); break;
	case SPDM_DOBJ_ID_REPORT: n = sizeof(struct spdm_dobj_hdr_report); break;
	default: n = 0; break;
	}

	return n;
}

#define SPDM_DOBJ_HDR_SIZE(hdr)		sla_dobj_id_to_size((hdr)->id)
#define SPDM_DOBJ_DATA(hdr)		((u8 *)(hdr) + SPDM_DOBJ_HDR_SIZE(hdr))
#define SPDM_DOBJ_LEN(hdr)		((hdr)->length - SPDM_DOBJ_HDR_SIZE(hdr))

static struct sla_buffer_hdr *sla_to_buffer(sla_addr_t sla)
{
	void *p;
	struct sla_buffer_hdr *buf;

	if (IS_SLA_NULL(sla) || sla.pfn == SLA_EOL)
		return NULL;

	p = __va(sla.pfn << PAGE_SHIFT);
	if (sla.page_type == SLA_PAGE_TYPE_SCATTER)
		buf = p + PAGE_SIZE;
	else
		buf = p;

	return buf;
}

#define sla_to_dobj_hdr(sla)		__sla_to_dobj_hdr((sla), SPDM_DOBJ_ID_NONE)
#define sla_to_dobj_resp_hdr(sla)	((struct spdm_dobj_hdr_resp *) \
					__sla_to_dobj_hdr((sla), SPDM_DOBJ_ID_RESP))
#define sla_to_dobj_req_hdr(sla)	((struct spdm_dobj_hdr_req *) \
					__sla_to_dobj_hdr((sla), SPDM_DOBJ_ID_REQ))
#define sla_to_dobj_cert_hdr(sla)	((struct spdm_dobj_hdr_cert *) \
					__sla_to_dobj_hdr((sla), SPDM_DOBJ_ID_CERTIFICATE))
#define sla_to_dobj_meas_hdr(sla)	((struct spdm_dobj_hdr_meas *) \
					__sla_to_dobj_hdr((sla), SPDM_DOBJ_ID_MEASUREMENT))
#define sla_to_dobj_report_hdr(sla)	((struct spdm_dobj_hdr_report *) \
					__sla_to_dobj_hdr((sla), SPDM_DOBJ_ID_REPORT))

static struct spdm_dobj_hdr *__sla_to_dobj_hdr(sla_addr_t sla, u32 type)
{
	struct sla_buffer_hdr *buf = sla_to_buffer(sla);
	struct spdm_dobj_hdr *hdr;

	if (!buf)
		return NULL;

	hdr = (struct spdm_dobj_hdr *) &buf[1];
	if (WARN_ON(type != SPDM_DOBJ_ID_NONE && hdr->id != type))
		return NULL;

	return hdr;
}

/**
 * struct sev_tio_info - TIO_INFO command's info_paddr buffer
 *
 * @length: Length of this structure in bytes
 * @tio_en: Indicates if SNP-IO feature is enabled.
 *	Controlled by SEV_INIT_FLAGS_SEV_TIO_EN parameter of SNP_INIT_EX.
 * @req_length_hint: Hint for SPDM request buffer length
 * @rsp_length_hint: Hint for SPDM response buffer length
 * @scratch_length_hint: Hint for SPDM scratch buffer length
 * @out_length_hint: Hint for SPDM output buffer length
*/
struct sev_tio_status {
	u32 length;
	union {
		u32 flags;
		struct {
			u32 tio_en:1;
		};
	};
	u32 spdm_req_size_hint;
	u32 spdm_scratch_size_hint;
	u32 spdm_out_size_hint;
	u32 devctx_size;
	u32 tdictx_size;
	u32 reserved;
};

static struct sev_tio_status *tio_status;

/**
 * struct sev_data_tio_status - SEV_CMD_TIO_STATUS command
 *
 * @length: Length of this command buffer in bytes
 * @info_length: Length of the buffer to write the sev_tio_info structure
 * @info_paddr: SPA of the buffer to write the sev_tio_info structure
*/
struct sev_data_tio_status {
	u32 length;				/* In */
	u32 reserved;			/* In */
	u64 status_paddr; 			/* In */
} __packed;


/**
 * struct sev_data_tio_dev_create - TIO_DEV_CREATE command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure
 * @dev_ctx_paddr: SPA of page donated by hypervisor
 * @rid: Routing ID of function 0 of the device (Bus:Device.Fn)
 * @tc_count: Number of traffic classes enabled in the device
 * @cert_slot: Slot number of the certificate requested for constructing the SPDM session
 */
struct sev_data_tio_dev_create {
	u32 length;				/* In */
	u32 reserved;
	sla_addr_t dev_ctx_sla;			/* In */
} __packed;

int sev_tio_dev_create(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm);

struct sev_data_tio_dev_connect {
	u32 length; // LENGTH Length in bytes of this command buffer.
	u32 reserved1; // 4h–7h – – Reserved.
	struct spdm_ctrl spdm_ctrl; // SPDM_CTRL SPDM control structure defined in Section 5.1.
	u16 device_id; // DEVICE_ID The PCIe Routing Identifier of the device to connect to.
	u16 root_port_id; // ROOT_PORT_ID The PCIe Routing Identifier of the root port of the device.
	u8 segment_id; // SEGMENT_ID The PCIe Segment Identifier of the device to connect to.
	u8 reserved2[3]; // 2Dh–2Fh – – Reserved.
	sla_addr_t dev_ctx_sla; // Scatter list address of the device context buffer.
	u8 tc_mask; // Bitmask of the traffic classes to initialize for SEV-TIO usage.
	u8 cert_slot; // Slot number of the certificate requested for constructing the SPDM session.
	u8 reserved3[6]; // 3Ah–3Fh – – Reserved
} __packed;

struct sev_data_tio_dev_disconnect {
	u32 length; // LENGTH Length in bytes of this command buffer.
	u32 reserved1; // 4h–7h – – Reserved.
	struct spdm_ctrl spdm_ctrl; // SPDM_CTRL SPDM control structure defined in Section 5.1.
	sla_addr_t dev_ctx_sla; // Scatter list address of the device context buffer.
} __packed;

/**
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure
 * @dev_ctx_paddr: SPA of page donated by hypervisor
 */
struct sev_data_tio_dev_meas {
	u32 length;				/* In */
	union {
		u32 flags;
		struct {
			u32 raw_bitstream:1;
		};
	};
	struct spdm_ctrl spdm_ctrl;		/* In */
	sla_addr_t dev_ctx_sla;			/* In */
} __packed;

int sev_tio_dev_measurements(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm, struct tsm_blob **meas);

/**
 * struct sev_data_tio_dev_reclaim - TIO_DEV_RECLAIM command
 *
 * @length: Length in bytes of this command buffer
 * @dev_ctx_paddr: SPA of page donated by hypervisor
 */
struct sev_data_tio_dev_reclaim {
	u32 length;				/* In */
	u32 reserved;				/* In */
	sla_addr_t dev_ctx_sla;			/* In */
} __packed;

/**
 * struct sev_tio_dev_status - sev_data_tio_dev_status::status_paddr of
 * TIO_DEV_STATUS command
 *
 */
struct sev_tio_dev_status {
	u32 length;
	u8 ctx_state;
	u8 tc_mask;
	union {
		u8 p1;
		struct {
			u8 request_pending:1;
			u8 request_pending_tdi:1;
		};
	};
	u8 certs_slot;
	u16 device_id;
	u8 segment_id;
	u8 tc_mask_again; // FIXME
	u16 request_pending_command;
	struct tdisp_interface_id request_pending_interface_id;
	union {
		u8 p2;
		struct {
			u8 meas_digest_valid:1;
			u8 no_fw_update:1;
		};
	};
	u8 reserved1[3];
	u16 ide_stream_id[8];
	u8 certs_digest[48];
	u8 meas_digest[48];
} __packed;

/**
 * struct sev_data_tio_dev_status - TIO_DEV_STATUS command
 *
 * @length: Length in bytes of this command buffer
[FIXME: spec says here "Reserved. Should be zero."]
 * @dev_ctx_paddr: SPA of a device context page
 * @status_length: Length in bytes of the sev_tio_dev_status buffer
 * @status_paddr: SPA of the status buffer. See Table 16
*/
struct sev_data_tio_dev_status {
	u32 length;				/* In */
	/* FIXME: Spec says here "reserved" */
	sla_addr_t dev_ctx_paddr;		/* In */
	u32 status_length;			/* In */
	u64 status_paddr;			/* In */
} __packed;

int sev_tio_dev_status(struct tsm_dev_tio *dev_data, struct tsm_dev_status *status);

/**
 * struct sev_data_tio_tdi_create - TIO_TDI_CREATE command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure
 * @dev_ctx_paddr: SPA of a device context page
 * @tdi_ctx_paddr: SPA of page donated by hypervisor
 * @interface_id: Interface ID of the TDI as defined by TDISP (host PCIID)
 */
struct sev_data_tio_tdi_create {
	u32 length;				/* In */
	u32 reserved;
	sla_addr_t dev_ctx_sla;			/* In */
	sla_addr_t tdi_ctx_sla;			/* In */
	struct tdisp_interface_id interface_id;	/* In */
} __packed;

struct sev_data_tio_tdi_reclaim {
	u32 length;				/* In */
	u32 reserved;
	sla_addr_t dev_ctx_sla;			/* In */
	sla_addr_t tdi_ctx_sla;			/* In */
} __packed;

/*
 * struct sev_data_tio_tdi_bind - TIO_TDI_BIND command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Chapter 2.
 * @tdi_ctx_paddr: SPA of page donated by hypervisor
 * @guest_ctx_paddr: SPA of guest context page
 * @flags:
 *  4 ALL_REQUEST_REDIRECT Requires ATS translated requests to route through the root complex. Must be 1.
 *  3 BIND_P2P Enables direct P2P. Must be 0
 *  2 LOCK_MSIX Lock the MSI-X table and PBA.
 *  1 CACHE_LINE_SIZE Indicates the cache line size. 0 indicates 64B. 1 indicates 128B. Must be 0.
 *  0 NO_FW_UPDATE Indicates that no firmware updates are allowed while the interface is locked.
 * @mmio_reporting_offset: Offset added to the MMIO range addresses in the interface report.
 * @guest_interface_id: Hypervisor provided identifier used by the guest to identify the TDI in guest messages
 */
struct sev_data_tio_tdi_bind {
	u32 length;				/* In */
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;		/* In */
	sla_addr_t dev_ctx_sla;
	sla_addr_t tdi_ctx_sla;
	u64 gctx_paddr;
	u16 guest_device_id;
	union {
		u16 flags;
		// These are TDISP's LOCK_INTERFACE_REQUEST flags
		struct {
			u16 no_fw_update : 1;
			u16 reservedf1 : 1;
			u16 lock_msix : 1;
			u16 bind_p2p : 1;
			u16 all_request_redirect : 1;
		};
	} tdisp_lock_if;
	u16 reserved2;
} __packed;

/*
 * struct sev_data_tio_tdi_unbind - TIO_TDI_UNBIND command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Chapter 2.
 * @tdi_ctx_paddr: SPA of page donated by hypervisor
 */
struct sev_data_tio_tdi_unbind {
	u32 length;				/* In */
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;		/* In */
	sla_addr_t dev_ctx_sla;
	sla_addr_t tdi_ctx_sla;
	u64 gctx_paddr;			/* In */
} __packed;

/**
 * struct sev_data_tio_guest_request - TIO_GUEST_REQUEST command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Chapter 2.
 * @gctx_paddr: system physical address of guest context page
 * @tdi_ctx_paddr: SPA of page donated by hypervisor
 * @req_paddr: system physical address of request page
 * @res_paddr: system physical address of response page
 */
struct sev_data_tio_guest_request {
	u32 length;				/* In */
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;		/* In */
	sla_addr_t dev_ctx_sla;
	sla_addr_t tdi_ctx_sla;
	u64 gctx_paddr;
	u64 req_paddr;				/* In */
	u64 res_paddr;				/* In */
} __packed;


static int __sev_tio_do_cmd_locked(int cmd, void *data, int *psp_ret,
				   struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct spdm_dobj_hdr_resp *resp_hdr = NULL;
	struct spdm_dobj_hdr_req *req_hdr;
	int rc, n = 0;

	if (dev_data)
		resp_hdr = sla_to_dobj_resp_hdr(dev_data->resp);

	/*
	 * TODO: make sure only one SPDM request is in flight at the time.
	 * Non-SPDM-aware commands can still execute.
	 */
	while (1) {
		rc = __sev_do_cmd_locked(cmd, data, psp_ret);
		if (*psp_ret != SEV_RET_TIO_SPDM_REQUEST)
			break;

		if (spdm)
			break;

		req_hdr = sla_to_dobj_req_hdr(dev_data->req);
		rc = spdm->cb(spdm, req_hdr->spdm_type != 0);
		if (rc)
			break;

		resp_hdr->spdm_type = req_hdr->spdm_type;

		++n;
		if (WARN_ON(n > 10))
			break;
	}

	if (rc || psp_ret)
		pr_err("___K___ %s %u: sev_tio(%x) -> rc=%d psp=%d\n", __func__, __LINE__,
			cmd, rc, *psp_ret);

	return rc;
}

int sev_tio_guest_request(void *data, int *fw_err, u32 guest_rid, u64 gctx_paddr,
			  struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	int ret;

	mutex_lock(&sev_cmd_mutex);
	ret = __sev_tio_do_cmd_locked(SEV_CMD_TIO_GUEST_REQUEST, data, fw_err, dev_data, spdm);
	mutex_unlock(&sev_cmd_mutex);

	return ret;
}

static void *sla_to_data(sla_addr_t sla, u8 id)
{
	struct spdm_dobj_hdr *hdr = sla_to_dobj_hdr(sla);
	return ((u8 *) hdr) + sla_dobj_id_to_size(id);
}

#define sla_alloc(l, fs) sla_alloc_dobj((l), SPDM_DOBJ_ID_NONE, (fs))
static sla_addr_t sla_alloc_dobj(size_t len, u8 id, bool firmware_state)
{
	struct sla_buffer_hdr *buf;
	unsigned long i, npages = PAGE_ALIGN(len) >> PAGE_SHIFT, pfn;
	sla_addr_t ret = { 0 };
	void *p;
	sla_addr_t *scatter = NULL;

	BUG_ON(npages > ((PAGE_SIZE / sizeof(sla_addr_t)) + 1));

	BUILD_BUG_ON(PAGE_SIZE < SZ_4K);
// PSP cannot handle DATA buffers properly yet
//	if (npages == 1) {
//		ret.page_type = SLA_PAGE_TYPE_DATA;
//		p = alloc_pages_exact(PAGE_SIZE, GFP_KERNEL | __GFP_ZERO);
//	} else {
		ret.page_type = SLA_PAGE_TYPE_SCATTER;
		p = alloc_pages_exact((npages + 1) << PAGE_SHIFT, GFP_KERNEL | __GFP_ZERO);
//	}
	if (!p)
		return SLA_NULL;

	pfn = __pa(p) >> PAGE_SHIFT;
	ret.pfn = pfn;
	ret.page_size = SLA_PAGE_SIZE_4K;

	buf = sla_to_buffer(ret);
	buf->capacity = (npages << PAGE_SHIFT);// - sizeof(struct sla_buffer_hdr);
	buf->size = 0;//buf->capacity - sizeof(*buf);

	if (ret.page_type == SLA_PAGE_TYPE_SCATTER) {
		scatter = p;
		for (i = 0; i < npages; ++i) {
			scatter[i].pfn = (pfn + i + 1);// | (__psp_pa(0) >> PAGE_SHIFT);
			scatter[i].page_type = SLA_PAGE_TYPE_DATA;
			scatter[i].page_size = SLA_PAGE_SIZE_4K;
		}
		scatter[i].pfn = SLA_EOL;
	}

	if (id != SPDM_DOBJ_ID_NONE && !firmware_state) {
		struct spdm_dobj_hdr *dobj = sla_to_dobj_hdr(ret);

		dobj->id = id;
		dobj->version.major = 0x1;
		dobj->version.minor = 0;
		buf->size = sizeof(*buf);//+ sla_dobj_id_to_size(id);
		// any id and buf->size not set -> psp=0x8003 SEV_RET_ERR_INVALID_PARAMS
		// any id and buf->size is set -> psp=0x3 INVALID_CONFIG
	}

	if (firmware_state) {
		if (ret.page_type == SLA_PAGE_TYPE_SCATTER) {
			for (i = 0; i < npages; ++i) {
				if (rmp_make_private(pfn + i + 1, 0, PG_LEVEL_4K, 0, true)) {
					for (unsigned j = 0; j < i; ++j)
						snp_reclaim_pages((pfn + j + 1) << PAGE_SHIFT, 1, true);
					return SLA_NULL;
				}
			}
		} else {
			rmp_make_private(pfn, 0, PG_LEVEL_4K, 0, true);
		}
	}

	return ret;
}

static void sla_free(sla_addr_t sla, size_t len, bool firmware_state)
{
	unsigned int npages = PAGE_ALIGN(len) >> PAGE_SHIFT;
	unsigned long pfn = sla.pfn;
	int ret = 0;

	if (!pfn)
		return;

	if (firmware_state) {
		if (sla.page_type == SLA_PAGE_TYPE_SCATTER) {
			sla_addr_t *scatter = __va(sla.pfn << PAGE_SHIFT);

			for (unsigned i = 0; i < npages; ++i)
			{
				if (scatter[i].pfn == SLA_EOL)
					break;
				pr_err("Reclaiming %llx\n", (u64)scatter[i].pfn << PAGE_SHIFT);
				ret = snp_reclaim_pages(scatter[i].pfn << PAGE_SHIFT, 1, true);
				// FIXME:
				if (ret)
					break;
			}
			npages += 1;
		} else {
			pr_err("Reclaiming %llx\n", (u64)sla.pfn << PAGE_SHIFT);
			ret = snp_reclaim_pages(sla.pfn << PAGE_SHIFT, 1, true);
		}
	}

	// Failed to reclaim so memory leaked (yeah I do not get this either)
	if (!ret)
	{
		pr_err("___K___ %s %u: No freeing memory! %lx sz=%lx\n", __func__, __LINE__,
			(unsigned long) pfn << PAGE_SHIFT, (unsigned long)npages << PAGE_SHIFT);
		if (0)
			free_pages_exact(__va(pfn << PAGE_SHIFT), npages << PAGE_SHIFT);
	}
}

static void tio_dev_sla_free(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	spdm->rsp = NULL;
	spdm->req = NULL;

	sla_free(dev_data->req, spdm->req_len, true);
	sla_free(dev_data->resp, spdm->rsp_len, false);
	sla_free(dev_data->scratch, dev_data->scratch_len, true);
	dev_data->req.sla = 0;
	dev_data->resp.sla = 0;
	dev_data->scratch.sla = 0;
}

static void tio_blob_release(struct tsm_blob *b)
{
	memset(b->data, 0, b->len);
}

static void sev_tsm_spdm_ctrl_hdr(struct spdm_ctrl *ctrl,
				  struct tsm_dev_tio *dev_data,
				  sla_addr_t output)
{
	ctrl->req = dev_data->req;
	ctrl->resp = dev_data->resp;
	ctrl->scratch = dev_data->scratch;
	ctrl->output = output;
}

static int sev_tio_status(void)
{
	struct sev_data_tio_status data_status = {
		.length = sizeof(data_status),
		.status_paddr = __psp_pa(tio_status),
	};
	int ret = 0, psp_ret = 0;

	/* FIXME: put the right version here or drop the check? */
	if (!sev_version_greater_or_equal(1, 54))
		return -ENOTSUPP;

	if (!tio_status) {
		tio_status = kzalloc(sizeof(*tio_status), GFP_KERNEL);
		// "8-byte aligned, and does not cross a page boundary"
		// BUG_ON(tio_status & 7);
		// BUG_ON(tio_status & ~PAGE_MASK > PAGE_SIZE - sizeof(*tio_status));

		if (!tio_status)
			tio_status = ERR_PTR(-ENOMEM);
		else
			data_status.status_paddr = __psp_pa(tio_status);
	}

	if (IS_ERR(tio_status))
		return PTR_ERR(tio_status);

	if (!tio_status->length) {
		tio_status->length = sizeof(*tio_status);

		ret = __sev_do_cmd_locked(SEV_CMD_TIO_STATUS, &data_status, &psp_ret);
	}

	if (ret || !tio_status->tio_en) {
		kfree(tio_status);
		tio_status = ERR_PTR(-ENOTSUPP);
	}

	return 0;
}

int sev_tio_dev_create(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct sev_data_tio_dev_create create = {
		.length = sizeof(create),
	};
	int ret, psp_ret = 0;


	ret = sev_tio_status();
	if (ret)
		return ret;

	dev_data->dev_ctx = sla_alloc(tio_status->devctx_size, true);
	if (IS_SLA_NULL(dev_data->dev_ctx)) {
		ret = -ENOMEM;
		goto free_exit;
	}
	dev_data->dev_ctx_len = tio_status->devctx_size;

	create.dev_ctx_sla = dev_data->dev_ctx;
	ret = __sev_do_cmd_locked(SEV_CMD_TIO_DEV_CREATE, &create, &psp_ret);
	if (ret) {
		ret = -EFAULT;
		goto free_exit;
	}

	return 0;

free_exit:
	tio_dev_sla_free(dev_data, spdm);
	return ret;
}

void sev_tio_dev_reclaim(struct tsm_dev_tio *dev_data)
{
	struct sev_data_tio_dev_reclaim r = {
		.length = sizeof(r),
		.dev_ctx_sla = dev_data->dev_ctx,
	};
	int ret, psp_ret = 0;

	if (IS_SLA_NULL(dev_data->dev_ctx))
		return;

	mutex_lock(&sev_cmd_mutex);
	ret = __sev_do_cmd_locked(SEV_CMD_TIO_DEV_RECLAIM, &r, &psp_ret);
	mutex_unlock(&sev_cmd_mutex);

	sla_free(dev_data->dev_ctx, dev_data->dev_ctx_len, true);
	dev_data->dev_ctx = SLA_NULL;
	dev_data->dev_ctx_len = 0;
}

int sev_tio_dev_connect(struct tsm_dev_tio *dev_data, u16 device_id, u16 root_port_id, u8 segment_id,
			u8 tc_mask, u8 cert_slot, struct tsm_spdm *spdm, struct tsm_blob **certs)
{
	struct sev_data_tio_dev_connect connect = {
		.length = sizeof(connect),
		.device_id = device_id,
		.root_port_id = root_port_id,
		.segment_id = segment_id,
		.tc_mask = tc_mask,
		.cert_slot = cert_slot,
		.dev_ctx_sla = dev_data->dev_ctx,
	};
	struct spdm_dobj_hdr_cert *certhdr;
	int ret, psp_ret = 0;
	sla_addr_t output;

	BUG_ON(IS_SLA_NULL(dev_data->dev_ctx));
	if (!(tc_mask & 1))
		return -EINVAL;

	dev_data->req = sla_alloc(tio_status->spdm_req_size_hint, true);
	dev_data->resp = sla_alloc_dobj(tio_status->spdm_req_size_hint, SPDM_DOBJ_ID_RESP, false);
	dev_data->scratch = sla_alloc(tio_status->spdm_scratch_size_hint, true);
	output = sla_alloc(tio_status->spdm_out_size_hint, true);

	if (IS_SLA_NULL(dev_data->req) || IS_SLA_NULL(dev_data->resp) ||
	    IS_SLA_NULL(dev_data->scratch) || IS_SLA_NULL(dev_data->dev_ctx)) {
		ret = -ENOMEM;
		goto free_spdm_exit;
	}

	spdm->req_len = tio_status->spdm_req_size_hint;
	spdm->rsp_len = tio_status->spdm_req_size_hint;
	dev_data->scratch_len = tio_status->spdm_scratch_size_hint;

	spdm->req = sla_to_data(dev_data->req, SPDM_DOBJ_ID_REQ);
	spdm->rsp = sla_to_data(dev_data->resp, SPDM_DOBJ_ID_RESP);
	if (!spdm->req || !spdm->rsp) {
		ret = -EFAULT;
		goto free_spdm_exit;
	}

	sev_tsm_spdm_ctrl_hdr(&connect.spdm_ctrl, dev_data, output);

	mutex_lock(&sev_cmd_mutex);
	ret = __sev_tio_do_cmd_locked(SEV_CMD_TIO_DEV_CONNECT, &connect, &psp_ret, dev_data, spdm);
	mutex_unlock(&sev_cmd_mutex);
	if (ret)
		goto free_spdm_exit;

	certhdr = sla_to_dobj_cert_hdr(output);
	if (certhdr)
		*certs = tsm_blob_new(SPDM_DOBJ_DATA(&certhdr->hdr), certhdr->hdr.length,
				      tio_blob_release);

	return 0;

free_spdm_exit:
	sla_free(output, tio_status->spdm_out_size_hint, true);
	tio_dev_sla_free(dev_data, spdm);

	return ret;
}

void sev_tio_dev_disconnect(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct sev_data_tio_dev_disconnect dc = {
		.length = sizeof(dc),
		.dev_ctx_sla = dev_data->dev_ctx,
	};
	int ret, psp_ret = 0;

	BUG_ON(IS_SLA_NULL(dev_data->dev_ctx));

	sev_tsm_spdm_ctrl_hdr(&dc.spdm_ctrl, dev_data, SLA_NULL);

	mutex_lock(&sev_cmd_mutex);
	ret = __sev_tio_do_cmd_locked(SEV_CMD_TIO_DEV_DISCONNECT, &dc, &psp_ret, dev_data, spdm);
	mutex_unlock(&sev_cmd_mutex);

	tio_dev_sla_free(dev_data, spdm);
}

int sev_tio_dev_measurements(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm, struct tsm_blob **meas_blob)
{
	struct sev_data_tio_dev_meas meas = {
		.length = sizeof(meas),
		.raw_bitstream = 1,
	};
	struct spdm_dobj_hdr_meas *meashdr;
	int ret, psp_ret = 0;
	sla_addr_t output;

	BUG_ON(IS_SLA_NULL(dev_data->dev_ctx));

	output = sla_alloc_dobj(tio_status->spdm_out_size_hint, SPDM_DOBJ_ID_MEASUREMENT, true);
	sev_tsm_spdm_ctrl_hdr(&meas.spdm_ctrl, dev_data, output);
	meas.dev_ctx_sla = dev_data->dev_ctx;

	mutex_lock(&sev_cmd_mutex);
	ret = __sev_tio_do_cmd_locked(SEV_CMD_TIO_DEV_MEASUREMENTS, &meas, &psp_ret, dev_data, spdm);
	mutex_unlock(&sev_cmd_mutex);
	if (ret)
		goto free_spdm_exit;

	meashdr = sla_to_dobj_meas_hdr(output);
	if (meashdr)
		*meas_blob = tsm_blob_new(SPDM_DOBJ_DATA(&meashdr->hdr), SPDM_DOBJ_LEN(&meashdr->hdr),
					  tio_blob_release);

	return 0;

free_spdm_exit:
	sla_free(output, tio_status->spdm_out_size_hint, true);

	return ret;
}

int sev_tio_dev_status(struct tsm_dev_tio *dev_data, struct tsm_dev_status *s)
{
	struct sev_tio_dev_status status = { .length = sizeof(status) };
	struct sev_data_tio_dev_status data_status = {
		.length = sizeof(data_status),
		.dev_ctx_paddr = dev_data->dev_ctx,
		.status_length = sizeof(status),
		.status_paddr = __psp_pa(&status),
	};
	int ret, psp_ret = 0;

	if (IS_SLA_NULL(dev_data->dev_ctx))
		return -ENXIO;

	mutex_lock(&sev_cmd_mutex);
	ret = __sev_do_cmd_locked(SEV_CMD_TIO_DEV_STATUS, &data_status, &psp_ret);
	mutex_unlock(&sev_cmd_mutex);
	if (ret)
		return ret;

	s->ctx_state = status.ctx_state;
	s->device_id = status.device_id;
	s->tc_mask = status.tc_mask;
//	memcpy(s->ide_stream_id, status.ide_stream_id, sizeof(ustatus->ide_stream_id));
//	memcpy(s->certs_digest, status.certs_digest, sizeof(ustatus->certs_digest));
//	memcpy(s->meas_digest, status.meas_digest, sizeof(ustatus->meas_digest));
	s->certs_slot = status.certs_slot;
	s->no_fw_update = status.no_fw_update;

	return 0;
}

int sev_tio_tdi_create(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, u16 dev_id,
		       u8 rseg, u8 rseg_valid)
{
	struct sev_data_tio_tdi_create c = {
		.length = sizeof(c),
	};
	int ret;

	if (WARN_ON(!dev_data || !tdi_data))
		return -EPERM;

	BUG_ON(IS_SLA_NULL(dev_data->dev_ctx));
	BUG_ON(!IS_SLA_NULL(tdi_data->tdi_ctx));

	tdi_data->tdi_ctx = sla_alloc(tio_status->tdictx_size, true);
	if (IS_SLA_NULL(tdi_data->tdi_ctx))
		return -ENOMEM;

	tdi_data->tdi_ctx_len = tio_status->tdictx_size;

	c.dev_ctx_sla = dev_data->dev_ctx;
	c.tdi_ctx_sla = tdi_data->tdi_ctx;
	c.interface_id.rid = dev_id;
	c.interface_id.rseg = rseg;
	c.interface_id.rseg_valid = rseg_valid;
	c.tdi_ctx_sla = tdi_data->tdi_ctx;

	mutex_lock(&sev_cmd_mutex);
	ret = __sev_do_cmd_locked(SEV_CMD_TIO_TDI_CREATE, &c, NULL);
	mutex_unlock(&sev_cmd_mutex);
	if (ret)
		goto free_exit;

	return 0;

free_exit:
	sla_free(tdi_data->tdi_ctx, tdi_data->tdi_ctx_len, true);
	tdi_data->tdi_ctx = SLA_NULL;
	return ret;
}

void sev_tio_tdi_reclaim(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data)
{
	struct sev_data_tio_tdi_reclaim r = {
		.length = sizeof(r),
	};

	if (IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx))
		return;

	r.dev_ctx_sla = dev_data->dev_ctx;
	r.tdi_ctx_sla = tdi_data->tdi_ctx;

	mutex_lock(&sev_cmd_mutex);
	__sev_do_cmd_locked(SEV_CMD_TIO_TDI_RECLAIM, &r, NULL);
	mutex_unlock(&sev_cmd_mutex);

	sla_free(tdi_data->tdi_ctx, tdi_data->tdi_ctx_len, true);
	tdi_data->tdi_ctx = SLA_NULL;
}

int sev_tio_tdi_bind(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, __u32 guest_rid, u64 gctx_paddr,
		struct tsm_spdm *spdm, struct tsm_blob **report)
{
	struct spdm_dobj_hdr_report *reporthdr;
	struct sev_data_tio_tdi_bind b = {
		.length = sizeof(b),
	};
	int ret, psp_ret = 0;
	sla_addr_t output;

	BUG_ON(IS_SLA_NULL(dev_data->dev_ctx));
	BUG_ON(IS_SLA_NULL(tdi_data->tdi_ctx));

	output = sla_alloc_dobj(tio_status->spdm_out_size_hint, SPDM_DOBJ_ID_REPORT, true);
	sev_tsm_spdm_ctrl_hdr(&b.spdm_ctrl, dev_data, output);
	b.dev_ctx_sla = dev_data->dev_ctx;
	b.tdi_ctx_sla = tdi_data->tdi_ctx;
	b.gctx_paddr = tdi_data->gctx_paddr;

	mutex_lock(&sev_cmd_mutex);
	ret = __sev_tio_do_cmd_locked(SEV_CMD_TIO_TDI_BIND, &b, &psp_ret, dev_data, spdm);
	mutex_unlock(&sev_cmd_mutex);
	if (ret)
		goto free_spdm_exit;

	reporthdr = sla_to_dobj_report_hdr(output);
	if (reporthdr)
		*report = tsm_blob_new(SPDM_DOBJ_DATA(&reporthdr->hdr), SPDM_DOBJ_LEN(&reporthdr->hdr),
				       tio_blob_release);
	return 0;

free_spdm_exit:
	sla_free(output, tio_status->spdm_out_size_hint, true);

	return ret;
}

void sev_tio_tdi_unbind(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, struct tsm_spdm *spdm)
{
	struct sev_data_tio_tdi_unbind ub = {
		.length = sizeof(ub),
	};
	int ret, psp_ret = 0;

	if (WARN_ON(!tdi_data || !dev_data))
		return;
	BUG_ON(!tdi_data->gctx_paddr);

	sev_tsm_spdm_ctrl_hdr(&ub.spdm_ctrl, dev_data, SLA_NULL);
	ub.dev_ctx_sla = dev_data->dev_ctx;
	ub.tdi_ctx_sla = tdi_data->tdi_ctx;
	ub.gctx_paddr = tdi_data->gctx_paddr;

	mutex_lock(&sev_cmd_mutex);
	ret = __sev_tio_do_cmd_locked(SEV_CMD_TIO_TDI_UNBIND, &ub, &psp_ret, dev_data, spdm);
	mutex_unlock(&sev_cmd_mutex);
	WARN_ON(ret);
}

struct sev_tio_tdi_info_data {
	u32 length;
	struct tdisp_interface_id interface_id;
	union {
		u32 p1;
		struct {
			u32 meas_digest_valid:1;
			u32 meas_digest_fresh:1;
		};
	};
	union {
		u32 p2;
		struct {
			u32 no_fw_update:1;
			u32 cache_line_size:1;
			u32 lock_msix:1;
			u32 bind_p2p:1;
			u32 all_request_redirect:1;
		};
	};
	u16 reserved1;
	u64 spdm_algos;
	u8 certs_digest[48];
	u8 meas_digest[48];
	u8 interface_report_digest[48];
	u8 guest_report_id[16];
} __packed;

struct sev_data_tio_tdi_info {
	u32 length;
	u32 reserved1;
	sla_addr_t dev_ctx_sla;
	sla_addr_t tdi_ctx_sla;
	u32 status_length;
	u32 reserved2;
	u64 status_paddr;
} __packed;

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

int sev_tio_tdi_info(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, struct tsm_tdi_status *ts)
{
	struct sev_tio_tdi_info_data data = { .length = sizeof(data) };
	struct sev_data_tio_tdi_info info = {
		.length = sizeof(info),
		.dev_ctx_sla = dev_data->dev_ctx,
		.tdi_ctx_sla = tdi_data->tdi_ctx,
		.status_length = sizeof(data),
		.status_paddr = __psp_pa(&data),
	};
	int ret, psp_ret = 0;

	if (IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx))
		return -ENXIO;

	mutex_lock(&sev_cmd_mutex);
	ret = __sev_do_cmd_locked(SEV_CMD_TIO_TDI_INFO, &info, &psp_ret);
	mutex_unlock(&sev_cmd_mutex);
	if (ret)
		return ret;

	ts->id = data.interface_id;
	ts->meas_digest_valid = data.meas_digest_valid;
	ts->meas_digest_fresh = data.meas_digest_fresh;
	ts->no_fw_update = data.no_fw_update;
	ts->cache_line_size = data.cache_line_size == 0 ? 64 : 128;
	ts->lock_msix = data.lock_msix;
	ts->bind_p2p = data.bind_p2p;
	ts->all_request_redirect = data.all_request_redirect;

#define __ALGO(x, n, y) ((((x) & (0xFFUL << (n))) == TIO_SPDM_ALGOS_##y) ? (1ULL << TSM_TDI_SPDM_ALGOS_##y) : 0)
	ts->spdm_algos =
		__ALGO(data.spdm_algos, 0, DHE_SECP256R1) |
		__ALGO(data.spdm_algos, 0, DHE_SECP384R1) |
		__ALGO(data.spdm_algos, 8, AEAD_AES_128_GCM) |
		__ALGO(data.spdm_algos, 8, AEAD_AES_256_GCM) |
		__ALGO(data.spdm_algos, 16, ASYM_TPM_ALG_RSASSA_3072) |
		__ALGO(data.spdm_algos, 16, ASYM_TPM_ALG_ECDSA_ECC_NIST_P256) |
		__ALGO(data.spdm_algos, 16, ASYM_TPM_ALG_ECDSA_ECC_NIST_P384) |
		__ALGO(data.spdm_algos, 24, HASH_TPM_ALG_SHA_256) |
		__ALGO(data.spdm_algos, 24, HASH_TPM_ALG_SHA_384) |
		__ALGO(data.spdm_algos, 32, KEY_SCHED_SPDM_KEY_SCHEDULE);
#undef __ALGO
	memcpy(ts->certs_digest, data.certs_digest, sizeof(ts->certs_digest));
	memcpy(ts->meas_digest, data.meas_digest, sizeof(ts->meas_digest));
	memcpy(ts->interface_report_digest, data.interface_report_digest, sizeof(ts->interface_report_digest));
	memcpy(ts->guest_report_id, data.guest_report_id, sizeof(ts->guest_report_id));

	return 0;
}

struct sev_tio_tdi_status_data {
	u32 length;
	u8 tdisp_state;
	u8 reserved1[3];
} __packed;

struct sev_data_tio_tdi_status {
	u32 length;
	u32 reserved1;
	struct spdm_ctrl spdm_ctrl;
	sla_addr_t dev_ctx_sla;
	sla_addr_t tdi_ctx_sla;
	u32 status_length;
	u32 reserved2;
	u64 status_paddr;
} __packed;

#define TIO_TDISP_STATE_CONFIG_UNLOCKED 0
#define TIO_TDISP_STATE_CONFIG_LOCKED 1
#define TIO_TDISP_STATE_RUN 2
#define TIO_TDISP_STATE_ERROR 3

int sev_tio_tdi_status(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, struct tsm_tdi_status *ts,
		       struct tsm_spdm *spdm)
{
	struct sev_tio_tdi_status_data data = { .length = sizeof(data) };
	struct sev_data_tio_tdi_status status = {
		.length = sizeof(status),
		.dev_ctx_sla = dev_data->dev_ctx,
		.tdi_ctx_sla = tdi_data->tdi_ctx,
		.status_length = sizeof(data),
		.status_paddr = __psp_pa(&data),
	};
	int ret, psp_ret = 0;

	if (IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx))
		return -ENXIO;

	sev_tsm_spdm_ctrl_hdr(&status.spdm_ctrl, dev_data, SLA_NULL);

	mutex_lock(&sev_cmd_mutex);
	ret = __sev_do_cmd_locked(SEV_CMD_TIO_TDI_STATUS, &status, &psp_ret);
	mutex_unlock(&sev_cmd_mutex);
	if (ret)
		return ret;

	switch (data.tdisp_state) {
#define __TDISP_STATE(y) case TIO_TDISP_STATE_##y: ts->state = TDISP_STATE_##y; break
	__TDISP_STATE(CONFIG_UNLOCKED);
	__TDISP_STATE(CONFIG_LOCKED);
	__TDISP_STATE(RUN);
	__TDISP_STATE(ERROR);
#undef __TDISP_STATE
	}

	return 0;
}

int sev_tio_cmd_buffer_len(int cmd)
{
	switch (cmd) {
	case SEV_CMD_TIO_STATUS:		return sizeof(struct sev_data_tio_status);
	case SEV_CMD_TIO_DEV_CREATE:		return sizeof(struct sev_data_tio_dev_create);
	case SEV_CMD_TIO_DEV_RECLAIM:		return sizeof(struct sev_data_tio_dev_reclaim);
	case SEV_CMD_TIO_DEV_CONNECT:		return sizeof(struct sev_data_tio_dev_connect);
	case SEV_CMD_TIO_DEV_DISCONNECT:	return sizeof(struct sev_data_tio_dev_disconnect);
	case SEV_CMD_TIO_DEV_STATUS:		return sizeof(struct sev_data_tio_dev_status);
	case SEV_CMD_TIO_DEV_MEASUREMENTS:	return sizeof(struct sev_data_tio_dev_meas);
//	case SEV_CMD_TIO_DEV_CERTIFICATES:	return sizeof(struct sev_data_tio_dev_certs);
	case SEV_CMD_TIO_TDI_CREATE:		return sizeof(struct sev_data_tio_tdi_create);
	case SEV_CMD_TIO_TDI_RECLAIM:		return sizeof(struct sev_data_tio_tdi_reclaim);
	case SEV_CMD_TIO_TDI_BIND:		return sizeof(struct sev_data_tio_tdi_bind);
	case SEV_CMD_TIO_TDI_UNBIND:		return sizeof(struct sev_data_tio_tdi_unbind);
//	case SEV_CMD_TIO_TDI_REPORT:		return sizeof(struct sev_data_tio_tdi_report);
	case SEV_CMD_TIO_TDI_STATUS:		return sizeof(struct sev_data_tio_tdi_status);
	case SEV_CMD_TIO_GUEST_REQUEST:		return sizeof(struct sev_data_tio_guest_request);
//	case SEV_CMD_TIO_ASID_FENCE_CLEAR:	return sizeof(struct sev_data_tio_asid_fence_clear);
//	case SEV_CMD_TIO_ASID_FENCE_STATUS:	return sizeof(struct sev_data_tio_asid_fence_status);
	case SEV_CMD_TIO_TDI_INFO:		return sizeof(struct sev_data_tio_tdi_info);
	default:				return 0;
	}
}
