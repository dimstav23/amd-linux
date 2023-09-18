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

#include <linux/types.h>

/* SNP Guest message request */
struct snp_req_data {
	unsigned long req_gpa;
	unsigned long resp_gpa;
	unsigned long data_gpa;
	unsigned int data_npages;
};

#endif /* __VIRT_SEVGUEST_H__ */
