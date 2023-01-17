// SPDX-License-Identifier: GPL-2.0-only

#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/tsm.h>
#include <linux/kvm_host.h>

#define DRIVER_VERSION	"0.1"
#define DRIVER_AUTHOR	"aik@amd.com"
#define DRIVER_DESC	"TSM TDISP driver"

static struct {
	struct tsm_ops *ops;
	void *private_data;

	uint tc_count;
	uint cert_slot;
	uint scan;
	bool connect;
	bool validate;
} tsm;

module_param_named(tc_count, tsm.tc_count, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(tc_count, "Number of traffic classes enabled in the device");

module_param_named(cert_slot, tsm.cert_slot, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cert_slot, "Slot number of the certificate requested for constructing the SPDM session");

module_param_named(scan, tsm.scan, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(scan, "Scan for N TDISP devices");

module_param_named(connect, tsm.connect, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(connect, "Do \"connect\" on TDISP discovery (starts IDE)");

module_param_named(validate, tsm.validate, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(validate, "Do \"validate\" on TDISP discovery (starts TDISP, VM only)");

struct tsm_blob *tsm_blob_new(void *data, u32 len, void (*release)(struct tsm_blob *b))
{
	struct tsm_blob *b;

	if (!len || !data)
		return NULL;

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return NULL;

	b->data = data;
	b->len = len;
	b->release = release;
	kref_init(&b->kref);

	return b;
}
EXPORT_SYMBOL_GPL(tsm_blob_new);

static void tsm_blob_release(struct kref *kref)
{
	struct tsm_blob *b = container_of(kref, struct tsm_blob, kref);

	b->release(b);
	kfree(b);
}

struct tsm_blob *tsm_blob_get(struct tsm_blob *b)
{
	if (!b)
		return NULL;

	if (!kref_get_unless_zero(&b->kref))
		return NULL;

	return b;
}
EXPORT_SYMBOL_GPL(tsm_blob_get);

void tsm_blob_put(struct tsm_blob *b)
{
	if (!b)
		return;

	kref_put(&b->kref, tsm_blob_release);
}
EXPORT_SYMBOL_GPL(tsm_blob_put);

static void tsm_tdi_unbind(struct tsm_tdi *tdi);

static void tsm_tdev_devres_release(struct device *dev, void *res)
{
	struct tsm_tdi *tdi = res;

	tsm_tdi_unbind(tdi);
}

struct tsm_dev *tsm_dev_get(struct device *dev)
{
	struct tsm_dev *tdev = devres_find(dev, tsm_tdev_devres_release, NULL, NULL);

	return tdev;
}
EXPORT_SYMBOL_GPL(tsm_dev_get);

static void tsm_tdi_devres_release(struct device *dev, void *res)
{
}

struct tsm_tdi *tsm_tdi_get(struct device *dev)
{
	struct tsm_tdi *tdi = devres_find(dev, tsm_tdi_devres_release, NULL, NULL);

	return tdi;
}
EXPORT_SYMBOL_GPL(tsm_tdi_get);

static int spdm_forward(struct tsm_spdm *spdm, bool secured)
{
	u8 type = secured ? PCI_DOE_PROTOCOL_SECURED_CMA_SPDM : PCI_DOE_PROTOCOL_CMA_SPDM;
	struct pci_doe_mb *doe_mb = secured ? spdm->doe_mb_secured : spdm->doe_mb;
	int rc = pci_doe(doe_mb, PCI_VENDOR_ID_PCI_SIG, type,
			 spdm->req, spdm->req_len, spdm->rsp, spdm->rsp_len);

	return rc;
}

static ssize_t tsm_cert_slot_store(struct device *dev, struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	unsigned long val;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	tdev->cert_slot = val;

	return count;
}

static ssize_t tsm_cert_slot_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	dump_stack();
	return sysfs_emit(buf, "%u\n", tdev->cert_slot);
}

static DEVICE_ATTR_RW(tsm_cert_slot);

static ssize_t tsm_tc_count_store(struct device *dev, struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	unsigned long val;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	tdev->tc_count = val;

	return count;
}

static ssize_t tsm_tc_count_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	return sysfs_emit(buf, "%u\n", tdev->tc_count);
}

static DEVICE_ATTR_RW(tsm_tc_count);

static ssize_t tsm_dev_connect_store(struct device *dev, struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	unsigned long val;
	ssize_t ret;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	if (val) {
		ret = tsm.ops->dev_connect(tdev, tsm.private_data);
		if (ret)
			return ret;
	} else {
		tsm.ops->dev_reclaim(tdev, tsm.private_data);
	}

	tdev->connected = val;

	return count;
}

static ssize_t tsm_dev_connect_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	return sysfs_emit(buf, "%u\n", tdev->connected);
}

static DEVICE_ATTR_RW(tsm_dev_connect);

static ssize_t blob_show(struct tsm_blob *blob, char *buf)
{
	int n;

	if (!blob)
		return sysfs_emit(buf, "0 0\n");

	// FIXME: replace blob with structure
	n = snprintf(buf, PAGE_SIZE, "%u %u\n", blob->len, kref_read(&blob->kref));
	return n + hex_dump_to_buffer(blob->data, blob->len, 16, 1, buf, PAGE_SIZE - n, false);
}

static ssize_t tsm_certs_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);

	return blob_show(tdev->certs, buf);
}

static DEVICE_ATTR_RO(tsm_certs);

static ssize_t tsm_meas_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);

	return blob_show(tdev->meas, buf);
}

static DEVICE_ATTR_RO(tsm_meas);

static ssize_t tsm_dev_status_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	struct tsm_dev_status s = { 0 };
	int ret = tsm.ops->dev_status(tdev, tsm.private_data, &s);

	return sysfs_emit(buf, "ret=%d\n"
		"ctx_state=%x\n"
		"tc_mask=%x\n"
		"certs_slot=%x\n"
		"device_id=%x\n"
		"segment_id=%x\n"
		"no_fw_update=%x\n",
		ret,
		s.ctx_state,
		s.tc_mask,
		s.certs_slot,
		s.device_id,
		s.segment_id,
		s.no_fw_update);
}

static DEVICE_ATTR_RO(tsm_dev_status);

static struct attribute *host_dev_attrs[] = {
	&dev_attr_tsm_cert_slot.attr,
	&dev_attr_tsm_tc_count.attr,
	&dev_attr_tsm_dev_connect.attr,
	&dev_attr_tsm_certs.attr,
	&dev_attr_tsm_meas.attr,
	&dev_attr_tsm_dev_status.attr,
	NULL,
};
static const struct attribute_group host_dev_group = {
	.attrs = host_dev_attrs,
};

static struct attribute *guest_dev_attrs[] = {
	&dev_attr_tsm_certs.attr,
	&dev_attr_tsm_meas.attr,
	NULL,
};
static const struct attribute_group guest_dev_group = {
	.attrs = guest_dev_attrs,
};

static ssize_t tsm_tdi_bound_store(struct device *dev, struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct tsm_tdi *tdi = tsm_tdi_get(dev);
	unsigned long bdfn, kvmid;

	/*
	 * FIXME: the trick is how to find out the kvmid. For AMD SEV-SNP it is snp_context.
	 * This needs lots of ugly KVM plumbing.
	 */
	if (sscanf(buf, "%lx %lx", &bdfn, &kvmid) != count)
		return -EINVAL;

	if (kvmid)
		tsm_tdi_bind(tdi, bdfn, kvmid);
	else
		tsm_tdi_unbind(tdi);

	return count;
}

static ssize_t tsm_tdi_bound_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_tdi *tdi = tsm_tdi_get(dev);

	return sysfs_emit(buf, "%u\n", tdi->bindfd);
}

static DEVICE_ATTR_RW(tsm_tdi_bound);

static ssize_t tsm_tdi_validated_store(struct device *dev, struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct tsm_tdi *tdi = tsm_tdi_get(dev);
	unsigned long val;
	ssize_t ret;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	if (val) {
		ret = tsm.ops->tdi_validate(tdi, false, tsm.private_data);
		if (ret)
			return ret;
	} else {
		tsm.ops->tdi_validate(tdi, true, tsm.private_data);
	}

	tdi->validated = val;

	return count;
}

static ssize_t tsm_tdi_validated_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_tdi *tdi = tsm_tdi_get(dev);
	return sysfs_emit(buf, "%u\n", tdi->validated);
}

static DEVICE_ATTR_RW(tsm_tdi_validated);

static ssize_t tsm_report_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_tdi *tdi = tsm_tdi_get(dev);

	return blob_show(tdi->report, buf);
}

static DEVICE_ATTR_RO(tsm_report);

static char *spdm_algos_to_str(u64 algos, char *buf, size_t len)
{
	char *p = buf;

	*p = 0;
	for (unsigned i = 0; i < 64; ++i) {
#define __ALGO(x) if (algos & (1 << (TSM_TDI_SPDM_ALGOS_##x))) p += snprintf(p, p - buf, " "#x)
		__ALGO(DHE_SECP256R1);
		__ALGO(DHE_SECP384R1);
		__ALGO(AEAD_AES_128_GCM);
		__ALGO(AEAD_AES_256_GCM);
		__ALGO(ASYM_TPM_ALG_RSASSA_3072);
		__ALGO(ASYM_TPM_ALG_ECDSA_ECC_NIST_P256);
		__ALGO(ASYM_TPM_ALG_ECDSA_ECC_NIST_P384);
		__ALGO(HASH_TPM_ALG_SHA_256);
		__ALGO(HASH_TPM_ALG_SHA_384);
		__ALGO(KEY_SCHED_SPDM_KEY_SCHEDULE);
#undef __ALGO
	}
	return buf;
}

static ssize_t tsm_tdi_status_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_tdi *tdi = tsm_tdi_get(dev);
	struct tsm_tdi_status ts = { 0 };
	int ret = tsm.ops->tdi_status(tdi, tsm.private_data, &ts);
	char algos[256];

	return sysfs_emit(buf, "ret=%d\n"
		"meas_digest_fresh=%x\n"
		"meas_digest_valid=%x\n"
		"all_request_redirect=%x\n"
		"bind_p2p=%x\n"
		"lock_msix=%x\n"
		"no_fw_update=%x\n"
		"cache_line_size=%d\n"
		"algos=%256s\n"
		,
		ret,
		ts.meas_digest_fresh,
		ts.meas_digest_valid,
		ts.all_request_redirect,
		ts.bind_p2p,
		ts.lock_msix,
		ts.no_fw_update,
		ts.cache_line_size,
		spdm_algos_to_str(ts.spdm_algos, algos, sizeof(algos))
		);
	//u8 certs_digest[48];
	//u8 meas_digest[48];
	//u8 interface_report_digest[48];
	/* HV only */
	//struct tdisp_interface_id id;
	//u8 guest_report_id[16];
	//enum tsm_tdisp_state state;
}

static DEVICE_ATTR_RO(tsm_tdi_status);

static struct attribute *host_tdi_attrs[] = {
	&dev_attr_tsm_tdi_bound.attr,
	&dev_attr_tsm_report.attr,
	&dev_attr_tsm_tdi_status.attr,
	NULL,
};
static const struct attribute_group host_tdi_group = {
	.attrs = host_tdi_attrs,
};

static struct attribute *guest_tdi_attrs[] = {
	&dev_attr_tsm_tdi_validated.attr,
	&dev_attr_tsm_report.attr,
	&dev_attr_tsm_tdi_status.attr,
	NULL,
};
static const struct attribute_group guest_tdi_group = {
	.attrs = guest_tdi_attrs,
};

static int tsm_init_tdi(struct pci_dev *physfn, struct pci_dev *pdev)
{
	struct tsm_dev *tdev = tsm_dev_get(&physfn->dev);
	struct tsm_tdi *tdi;
	int ret = 0;

	if (!tdev)
		return -ENODEV;

	tdi = devres_alloc(tsm_tdi_devres_release, sizeof(*tdi), GFP_KERNEL);
	if (!tdi)
		return -ENOMEM;

	if (tsm.ops->dev_connect)
		tdi->ag = &host_tdi_group;
	else
		tdi->ag = &guest_tdi_group;

	ret = device_add_group(&pdev->dev, tdi->ag);
	if (ret)
		goto free_exit;

	tdi->tdev = tdev;
	tdi->pdev = pci_dev_get(pdev);
	tdi->bindfd = -1;
	devres_add(&pdev->dev, tdi);

	/*
	 * If tdi_info!=NULL, then this is a guest so trigger GHCB via KVM to let
	 * the host know that the guest is interested in TDISP. The host will
	 * initialize TDI in TSM and perform binding.
	 */
	if (tsm.ops->tdi_validate) {
		struct tsm_tdi_status ts;

		ret = tsm.ops->tdi_status(tdi, tsm.private_data, &ts);
		if (ret)
			goto pci_dev_put_exit;

		if (tsm.validate) {
			ret = tsm.ops->tdi_validate(tdi, false, tsm.private_data);
			if (ret)
				goto pci_dev_put_exit;
		}
	}
	return 0;

pci_dev_put_exit:
	pci_dev_put(pdev);
free_exit:
	devres_free(tdi);

	return ret;
}

static void tsm_free_tdi(struct tsm_tdi *tdi)
{
	if (tsm.ops->tdi_reclaim)
		tsm.ops->tdi_reclaim(tdi, tsm.private_data);

	pci_dev_put(tdi->pdev);

	device_remove_group(&tdi->pdev->dev, tdi->ag);
	devres_remove(&tdi->pdev->dev, tsm_tdi_devres_release, NULL, tdi);
	devres_free(tdi);
}

static int tsm_init_dev(struct pci_dev *pdev)
{
	struct tsm_dev *tdev;
	int ret = 0;

	tdev = devres_alloc(tsm_tdev_devres_release, sizeof(*tdev), GFP_KERNEL);
	if (!tdev)
		return -ENOMEM;

	tdev->tc_count = tsm.tc_count;
	tdev->cert_slot = tsm.cert_slot;
	tdev->pdev = pci_dev_get(pdev);

	if (tsm.ops->dev_connect)
		tdev->ag = &host_dev_group;
	else
		tdev->ag = &guest_dev_group;

	ret = device_add_group(&pdev->dev, tdev->ag);
	if (ret)
		return ret;

	if (tsm.ops->dev_connect) {
		tdev->pdev = pci_dev_get(pdev);
		tdev->spdm.doe_mb = pci_find_doe_mailbox(tdev->pdev,
							 PCI_VENDOR_ID_PCI_SIG,
							 PCI_DOE_PROTOCOL_CMA_SPDM);
		if (!tdev->spdm.doe_mb)
			goto pci_dev_put_exit;

		tdev->spdm.doe_mb_secured = pci_find_doe_mailbox(tdev->pdev,
								 PCI_VENDOR_ID_PCI_SIG,
								 PCI_DOE_PROTOCOL_SECURED_CMA_SPDM);
		if (!tdev->spdm.doe_mb_secured)
			goto pci_dev_put_exit;

		tdev->spdm.cb = spdm_forward;

		if (tsm.connect)
			ret = tsm.ops->dev_connect(tdev, tsm.private_data);
	}

	devres_add(&pdev->dev, tdev);
	return ret;

pci_dev_put_exit:
	pci_dev_put(pdev);
	kfree(tdev);

	return ret;
}

static void tsm_free_dev(struct tsm_dev *tdev)
{
	device_remove_group(&tdev->pdev->dev, tdev->ag);

	if (tdev->connected && tsm.ops->dev_reclaim)
		tsm.ops->dev_reclaim(tdev, tsm.private_data);

	pci_dev_put(tdev->pdev);

	devres_remove(&tdev->pdev->dev, tsm_tdev_devres_release, NULL, tdev);
	devres_free(tdev);
}

static int tsm_alloc_device(struct pci_dev *pdev)
{
	int ret = 0;

	if (pdev->is_physfn && pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_IDE)) {
		WARN_ON_ONCE(pdev->devfn & 7);

		ret = tsm_init_dev(pdev);
		if (ret)
			return ret;

		ret = tsm_init_tdi(pdev, pdev);
		if (ret)
			return ret;
	}

	if (pdev->is_virtfn && pci_find_ext_capability(pdev->physfn, PCI_EXT_CAP_ID_IDE)) {
		ret = tsm_init_tdi(pdev->physfn, pdev);
		if (ret)
			return ret;
	}

	return ret;
}

static void tsm_free_device(struct device *dev)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	struct tsm_tdi *tdi = tsm_tdi_get(dev);

	if (tdi)
		tsm_free_tdi(tdi);

	if (tdev)
		tsm_free_dev(tdev);
}

static int tsm_pci_bus_notifier(struct notifier_block *nb, unsigned long action, void *data)
{
	switch (action) {
	case BUS_NOTIFY_ADD_DEVICE:
		tsm_alloc_device(to_pci_dev(data));
		break;
	case BUS_NOTIFY_REMOVED_DEVICE:
		tsm_free_device(data);
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block tsm_pci_bus_nb = {
	.notifier_call = tsm_pci_bus_notifier,
};

static int __init tsm_init(void)
{
	int ret = 0;

	pr_info(DRIVER_DESC " version: " DRIVER_VERSION "\n");
	bus_register_notifier(&pci_bus_type, &tsm_pci_bus_nb);
	return ret;
}

static void __exit tsm_cleanup(void)
{
	bus_unregister_notifier(&pci_bus_type, &tsm_pci_bus_nb);
}

void tsm_set_ops(struct tsm_ops *ops, void *private_data)
{
	struct pci_dev *pdev = NULL;
	int ret;

	if (!tsm.ops && ops) {
		unsigned n = 0;

		tsm.ops = ops;
		tsm.private_data = private_data;

		for_each_pci_dev(pdev) {
			++n;
			if (n > tsm.scan)
				break;

			ret = tsm_alloc_device(pdev);
			if (ret)
				break;
		}
	} else {
		for_each_pci_dev(pdev)
			tsm_free_device(&pdev->dev);
		tsm.ops = ops;
	}
}
EXPORT_SYMBOL_GPL(tsm_set_ops);

static int tsm_tdi_bind_fops_fops_release(struct inode *inode, struct file *filep)
{
	struct tsm_tdi_binding *b = filep->private_data;

	if (!b->tdi)
		return 0;

	if (tsm.ops->tdi_reclaim)
		tsm.ops->tdi_reclaim(b->tdi, tsm.private_data);

	kfree(b);

	return 0;
}

const struct file_operations tsm_tdi_bind_fops = {
	.owner		= THIS_MODULE,
	.release	= tsm_tdi_bind_fops_fops_release,
};

int tsm_tdi_bind(struct tsm_tdi *tdi, u32 guest_rid, u64 kvmid)
{
	struct tsm_tdi_binding *b;
	char name[64];
	int ret;

	if (!tsm.ops->tdi_bind)
		return -EBADF;

	b = kzalloc(sizeof(b), GFP_KERNEL);
	if (!b)
		return -ENOMEM;

	ret = tsm.ops->tdi_bind(tdi, guest_rid, kvmid, tsm.private_data);
	if (ret)
		goto free_exit;

	snprintf(name, sizeof(name) - 1, "[tsm-%s]", pci_name(tdi->pdev));
	ret = anon_inode_getfd(name, &tsm_tdi_bind_fops, b, 0);
	if (ret < 0)
		goto free_exit;

	b->tdi = tdi;
	b->guest_rid = guest_rid;
	b->vmid = kvmid;
	return ret;

free_exit:
	kfree(b);
	return ret;
}
EXPORT_SYMBOL_GPL(tsm_tdi_bind);

static struct tsm_tdi_binding *fd_to_binding(int bindfd)
{
	struct fd f = fdget(bindfd);

	if (!f.file)
		return NULL;

	return f.file->private_data;
}

struct tsm_tdi *tsm_bindfd_to_tdi(int bindfd)
{
	struct tsm_tdi_binding *b = fd_to_binding(bindfd);

	if (!b)
		return NULL;

	return b->tdi;

}
EXPORT_SYMBOL_GPL(tsm_bindfd_to_tdi);

static void tsm_tdi_unbind(struct tsm_tdi *tdi)
{
	WARN_ON(tdi->bindfd < 0);
	close_fd(tdi->bindfd);
	tdi->bindfd = -1;
}

int tsm_guest_request(int fd, void *req_data, struct file *vfile)
{
	struct tsm_tdi_binding *b = fd_to_binding(fd);
	struct tsm_tdi *tdi = b->tdi;

	if (!tsm.ops->guest_request)
		return -EBADF;

	return tsm.ops->guest_request(tdi, b->guest_rid, b->vmid, req_data, vfile, tsm.private_data);
}
EXPORT_SYMBOL_GPL(tsm_guest_request);

int tsm_tdi_find(u32 guest_rid, u64 kvmid)
{
	struct pci_dev *pdev = NULL;
	struct tsm_tdi_binding *b;
	struct tsm_tdi *tdi;

	for_each_pci_dev(pdev) {
		tdi = tsm_tdi_get(&pdev->dev);

		if (!tdi)
			continue;

		b = fd_to_binding(tdi->bindfd);
		if (!b)
			continue;

		if (b->vmid == kvmid && b->guest_rid == guest_rid)
			return tdi->bindfd;
	}

	return -ENODEV;
}
EXPORT_SYMBOL_GPL(tsm_tdi_find);

module_init(tsm_init);
module_exit(tsm_cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_ALIAS_MISCDEV(TSM_MINOR);
MODULE_SOFTDEP("post: ccp");
