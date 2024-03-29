# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the kernel security code
#

obj-$(CONFIG_KEYS)			+= keys/
subdir-$(CONFIG_SECURITY_SELINUX)	+= selinux
subdir-$(CONFIG_SECURITY_SMACK)		+= smack
subdir-$(CONFIG_SECURITY_TOMOYO)        += tomoyo
subdir-$(CONFIG_SECURITY_APPARMOR)	+= apparmor
subdir-$(CONFIG_SECURITY_YAMA)		+= yama
subdir-$(CONFIG_SECURITY_LOADPIN)	+= loadpin
subdir-$(CONFIG_SECURITY_SAFESETID)    += safesetid
subdir-$(CONFIG_SECURITY_LOCKDOWN_LSM)	+= lockdown
subdir-$(CONFIG_HW_KERNEL_STP)		+= kernel_stp
subdir-$(CONFIG_HW_ROOT_SCAN)		+= hw_root_scan
subdir-$(CONFIG_HUAWEI_SOP)		+= sop
subdir-$(CONFIG_HUAWEI_EIMA)		+= eima

# always enable default capabilities
obj-y					+= commoncap.o
obj-$(CONFIG_MMU)			+= min_addr.o

# Object file lists
obj-$(CONFIG_SECURITY)			+= security.o
obj-$(CONFIG_SECURITYFS)		+= inode.o
obj-$(CONFIG_SECURITY_SELINUX)		+= selinux/
obj-$(CONFIG_SECURITY_SMACK)		+= smack/
obj-$(CONFIG_AUDIT)			+= lsm_audit.o
obj-$(CONFIG_SECURITY_TOMOYO)		+= tomoyo/
obj-$(CONFIG_SECURITY_APPARMOR)		+= apparmor/
obj-$(CONFIG_SECURITY_YAMA)		+= yama/
obj-$(CONFIG_SECURITY_LOADPIN)		+= loadpin/
obj-$(CONFIG_SECURITY_SAFESETID)       += safesetid/
obj-$(CONFIG_SECURITY_LOCKDOWN_LSM)	+= lockdown/
obj-$(CONFIG_CGROUP_DEVICE)		+= device_cgroup.o

# Object integrity file lists
subdir-$(CONFIG_INTEGRITY)		+= integrity
obj-$(CONFIG_INTEGRITY)			+= integrity/
obj-$(CONFIG_HW_KERNEL_STP)		+= kernel_stp/
obj-$(CONFIG_HW_ROOT_SCAN)		+= hw_root_scan/
obj-$(CONFIG_HUAWEI_SOP)		+= sop/
obj-$(CONFIG_HUAWEI_EIMA)		+= eima/

# HW Object
obj-$(CONFIG_HKIP_ATKINFO)		+= hkip_atkinfo/
obj-$(CONFIG_HUAWEI_PROC_CHECK_ROOT)    += check_root/
obj-$(CONFIG_KERNEL_HARDEN_DEBUG)       += kernel_harden_test/
include security/kernel_harden/Makefile
