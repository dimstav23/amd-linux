.. SPDX-License-Identifier: GPL-2.0

What it is
==========

This is for PCI passthrough in confidential computing (CoCo: SEV-SNP, TDX, CoVE).
Today passing through PCI devices to CoCo VMs is unsecure as so far PCI hardware
was not capable of accessing encrypted memory, therefore rather slow SWIOTLB is used.

PCIe IDE (Integrity and Data Encryption) and TDISP (TEE Device Interface Security
Protocol) are protocols to address those issues on supporting hardware which is
coming soon. Once set up, all PCIe trafic betweent the device and the SOC is
cryptographically encrypted, the VMM is prohibited from altering the device
configuration and accessing the MMIO; DMA trafic to/from the CoCo VM is encrypted
on the go.


Protocols
=========

A PCIe device capable of TDISP has a "TEE-IO" bit in PCIe extended capabilities.
A PCIe device needs to implement PCIe DOE mailbox protocol (yet another way of
sending/receiving large object to/from the device's configuration space).
On top of DOE, Security Protocol and Data Mode (SPDM) runs to allow secure sessons.
On top of SPDM, IDE_KM protocol runs - it is responsinble for setting up encryption
over the PCIe link.
Another protocol on top of SPDM is TDISP which fetches the device attestation report
and puts the device in a "locked" state after which the device can be used securely
by a CoCO VM.


TSM module
==========

Vendors take different approaches, however the initialization sequence and artefacts
(certificates, measurements, attestation report) are the same. The TSM module is
a common place. The module relies on a platform to provide a set of hooks, some
valid for a host, some for a guest. When the platform initializes the TSM module
with said hooks, the TSM module walks through PCI devices and initializes internal
structures and talks to the platform TSM to set up SPDM/IDE/TDISP. The TSM module
provides a few module parameters to control setup behavior and manages sysfs entries
for finer control.

Flow
====

1. The host boots
2. loads tsm.ko before TDISP capable device (modprobe.d adjustment needed)
3. loads ccp.ko which registers the tsm_ops (also loaded before the device driver)
4. when tsm_ops is set, tsm.ko performs the setup - creates data structures in
the secure firmware, receives measurements/certificates. After the setup is done,
the SPDM session is up and the PCIe link is IDE-encrypted.
5. the userspace can read the measurements/certificates via sysfs.

6. The CoCo VM boots
7. Similar to 2): loads tsm.ko before TDISP capable device
8. loads sev-guest.ko which registers the tsm_ops (also loaded before the device
driver); this tsm_ops is different as the VM does not have direct interface
to the firmware and relies on the VMM instead.
9. when the VM does the first request to the firmware, the host binds the passed
through device to the VM in the firmware which brings the device to the "locked"
state.
10. the VM's tsm.ko receives the attestation report, performs the validation
(Note: not vendor-specific bits at this point!) and requests the firmware to
perform the MMIO/VIOMMU validation which updates the RMP and sDTE tables to
make device actually work.


References
==========

[1] TEE Device Interface Security Protocol - TDISP - v2022-07-27
https://members.pcisig.com/wg/PCI-SIG/document/18268?downloadRevision=21500
[2] Security Protocol and Data Model (SPDM)
https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.2.1.pdf
