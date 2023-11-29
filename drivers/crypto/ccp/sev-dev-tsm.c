// SPDX-License-Identifier: GPL-2.0-only

// Interface to CCP/SEV-TIO for generic PCIe TDISP module

#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/tsm.h>

#include <asm/smp.h>
#include <asm/sev-common.h>

#include "psp-dev.h"
#include "sev-dev.h"
#include "sev-dev-tio.h"

static int tsm_dev_connect(struct tsm_dev *tdev, void *private_data)
{
	u16 device_id = pci_dev_id(tdev->pdev);
	u16 root_port_id = tdev->pdev->bus && tdev->pdev->bus->self ? pci_dev_id(tdev->pdev->bus->self) : 0;
	u8 segment_id = tdev->pdev->bus ? pci_domain_nr(tdev->pdev->bus) : 0;
	struct tsm_blob *certs, *meas;
	struct tsm_dev_tio *dev_data;
	int ret;

	dev_data = kzalloc(sizeof(*dev_data), GFP_KERNEL);
	if (!dev_data)
		return -ENOMEM;

	ret = sev_tio_dev_create(dev_data, &tdev->spdm);
	if (ret)
		goto free_exit;

	ret = sev_tio_dev_connect(dev_data, device_id, root_port_id, segment_id,
				  tdev->tc_count /* or mask? */, tdev->cert_slot,
				  &tdev->spdm, &certs);
	if (ret)
		goto reclaim_exit;

	tsm_blob_put(tdev->certs);
	tdev->certs = certs;

	ret = sev_tio_dev_measurements(dev_data, &tdev->spdm, &meas);
	if (ret)
		goto disconnect_exit;

	if (!ret) {
		tsm_blob_put(tdev->meas);
		tdev->meas = meas;
	}

	tdev->data = dev_data;

	return 0;

disconnect_exit:
	sev_tio_dev_disconnect(dev_data, &tdev->spdm);
reclaim_exit:
	sev_tio_dev_reclaim(dev_data);
free_exit:
	kfree(dev_data);

	return ret;
}

static void tsm_dev_reclaim(struct tsm_dev *tdev, void *private_data)
{
	struct tsm_dev_tio *dev_data = tdev->data;

	if (!dev_data)
		return;

	sev_tio_dev_reclaim(tdev->data);
	kfree(tdev->data);
	tdev->data = NULL;
}

int tsm_dev_status(struct tsm_dev *tdev, void *private_data, struct tsm_dev_status *s)
{
	int ret;

	ret = sev_tio_dev_status(tdev->data, s);
	WARN_ON(s->device_id != pci_dev_id(tdev->pdev));

	return ret;
}

static void tsm_tdi_reclaim(struct tsm_tdi *tdi, void *private_data)
{
	sev_tio_tdi_unbind(tdi->tdev->data, tdi->data, &tdi->tdev->spdm);
	sev_tio_tdi_reclaim(tdi->tdev->data, tdi->data);

	kfree(tdi->data);
	tdi->data = NULL;
}

static int tsm_tio_tdi_bind(struct tsm_tdi *tdi, u32 bdfn, u64 kvmid, void *private_data)
{
	struct tsm_blob *report = NULL;
	int ret;
	struct tsm_tdi_tio *tdi_data;

	tdi_data = kzalloc(sizeof(*tdi_data), GFP_KERNEL);

	ret = sev_tio_tdi_create(tdi->tdev->data, tdi_data, pci_dev_id(tdi->pdev), tdi->rseg, tdi->rseg_valid);
	if (ret)
		return ret;

	ret = sev_tio_tdi_bind(tdi->tdev->data, tdi_data, bdfn, kvmid, &tdi->tdev->spdm, &report);
	if (ret)
		goto reclaim_exit;

	tdi->report = report;
	tdi->data = tdi_data;

	return ret;

reclaim_exit:
	sev_tio_tdi_reclaim(tdi->tdev->data, tdi_data);
	kfree(tdi_data);

	return ret;
}

static int tsm_tio_guest_request(struct tsm_tdi *tdi, u32 guest_rid, u64 kvmid, void *req_data,
	struct file *vfile, void *private_data)
{
	struct tio_guest_request *req = req_data;
	int rc;

	rc = sev_tio_guest_request(&req->data, &req->fw_err, guest_rid, kvmid,
				   tdi->tdev->data, &tdi->tdev->spdm);

	return rc;
}

static int tsm_tio_tdi_status(struct tsm_tdi *tdi, void *private_data, struct tsm_tdi_status *ts)
{
	struct tsm_tdi_status tstmp = { 0 };
	int ret;

	ret = sev_tio_tdi_status(tdi->tdev->data, tdi->data, &tstmp, &tdi->tdev->spdm);
	if (ret)
		return ret;

	ret = sev_tio_tdi_info(tdi->tdev->data, tdi->data, &tstmp);
	if (ret)
		return ret;

	*ts = tstmp;
	return 0;
}

struct tsm_ops sev_tsm_ops = {
	.dev_connect = tsm_dev_connect,
	.dev_reclaim = tsm_dev_reclaim,
	.dev_status = tsm_dev_status,
	.tdi_bind = tsm_tio_tdi_bind,
	.tdi_reclaim = tsm_tdi_reclaim,
	.guest_request = tsm_tio_guest_request,
	.tdi_status = tsm_tio_tdi_status,
};

void sev_tsm_set_ops(bool set)
{
	tsm_set_ops(set ? &sev_tsm_ops : NULL, NULL);
}
