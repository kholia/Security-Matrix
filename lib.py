#!/usr/bin/env python

# Copyright 2008-2010 Canonical, Ltd.
# Author: Kees Cook <kees@ubuntu.com>
# License: GPLv3
#
# Shamelessly stolen for Fedora
# Copyright 2013 Dhiru Kholia
# License: GPLv3

# import "raw" data
from data import feature_list

features = dict()

# releases = ["RHEL 3", "RHEL 4", "RHEL 5", "RHEL 6", "RHEL 7", \
releases = [
    "RHEL 3", "RHEL 4", "RHEL 5", "RHEL 6", "RHEL 7",
    "Fedora 19", "Fedora 24", "Rawhide"]
    # "Fedora 19", "Fedora 20", "Fedora 21", "Fedora 22",
    # "Fedora 23", "Fedora 24", "Rawhide"]

release_names = {
    "RHEL 3": "RHEL 3",
    "RHEL 4": "RHEL 4",
    "RHEL 5": "RHEL 5",
    "RHEL 6": "RHEL 6",
    "RHEL 7": "RHEL 7",
    "Fedora 19": "Fedora 19",
    "Fedora 20": "Fedora 20",
    "Fedora 21": "Fedora 21",
    "Fedora 22": "Fedora 22",
    "Fedora 23": "Fedora 23",
    "Fedora 24": "Fedora 24",
    "Rawhide": "Rawhide",
}

release_dates = {
    "RHEL 3": "2003 Oct",
    "RHEL 4": "2005 Feb",
    "RHEL 5": "2007 Mar",
    "RHEL 6": "2010 Nov",
    "RHEL 7": "2014 Jun",
    "Fedora 19": "2013 Jul",
    "Fedora 20": "2013 Dec",
    "Fedora 21": "2014 Dec",
    "Fedora 22": "2015 May",
    "Fedora 23": "2015 Nov",
    "Fedora 24": "2014 Jun",
    "Rawhide": "-",
}


UNIMPLEMENTED = 0
AVAILABLE = 1
DEFAULT = 2
color = {UNIMPLEMENTED: 'ffff00', AVAILABLE: '98fd98', DEFAULT: '00dd00'}

for details in feature_list:
    features.setdefault(details['name'], dict())
    for item in details.keys():
        if item == 'name':
            continue
        features[details['name']].setdefault(item, details[item])
    features[details['name']].setdefault('matrix', dict())
    for rel in releases:
        features[details['name']]['matrix'].setdefault(rel, dict())
        features[details['name']]['matrix'][rel].setdefault('status', '--')
        features[details['name']]['matrix'][rel].setdefault('state',
                                                            UNIMPLEMENTED)


def add_status(name, release, status, state):
    overwrite = False
    for rel in releases:
        if rel == release:
            overwrite = True
        if overwrite:
            features[name]['matrix'][rel]['status'] = status
            features[name]['matrix'][rel]['state'] = state

# fill up the "Security Matrix"

# firewall
add_status('firewall', 'RHEL 3', 'iptables', DEFAULT)
add_status('firewall', 'RHEL 4', 'iptables', DEFAULT)
add_status('firewall', 'RHEL 5', 'iptables', DEFAULT)
add_status('firewall', 'RHEL 6', 'iptables', DEFAULT)
add_status('firewall', 'RHEL 7', 'iptables', DEFAULT)
add_status('firewall', 'Fedora 19', 'firewalld', DEFAULT)
add_status('firewall', 'Fedora 20', 'firewalld', DEFAULT)
add_status('firewall', 'Fedora 21', 'firewalld', DEFAULT)
add_status('firewall', 'Fedora 22', 'firewalld', DEFAULT)
add_status('firewall', 'Fedora 23', 'firewalld', DEFAULT)
add_status('firewall', 'Fedora 24', 'firewalld', DEFAULT)
add_status('firewall', 'Rawhide', 'firewalld', DEFAULT)

# updates
add_status('updates', 'RHEL 3', 'yum', DEFAULT)
add_status('updates', 'RHEL 4', 'yum', DEFAULT)
add_status('updates', 'RHEL 5', 'yum', DEFAULT)
add_status('updates', 'RHEL 6', 'yum', DEFAULT)
add_status('updates', 'RHEL 7', 'yum', DEFAULT)
add_status('updates', 'Fedora 19', 'yum / dnf', DEFAULT)
add_status('updates', 'Fedora 20', 'yum / dnf', DEFAULT)
add_status('updates', 'Fedora 21', 'yum / dnf', DEFAULT)
add_status('updates', 'Fedora 22', 'yum / dnf', DEFAULT)
add_status('updates', 'Fedora 23', 'yum / dnf', DEFAULT)
add_status('updates', 'Fedora 24', 'yum / dnf', DEFAULT)
add_status('updates', 'Rawhide', 'yum / dnf', DEFAULT)

# NX stuff
add_status('nx', 'RHEL 3', 'Y (since 9/2004)', DEFAULT)
add_status('nx', 'RHEL 4', 'Y', DEFAULT)
add_status('nx', 'RHEL 5', 'Y', DEFAULT)
add_status('nx', 'RHEL 6', 'Y', DEFAULT)
add_status('nx', 'RHEL 7', 'Y', DEFAULT)
add_status('nx', 'Fedora 19', 'Y', DEFAULT)
add_status('nx', 'Fedora 20', 'Y', DEFAULT)
add_status('nx', 'Fedora 21', 'Y', DEFAULT)
add_status('nx', 'Fedora 22', 'Y', DEFAULT)
add_status('nx', 'Fedora 23', 'Y', DEFAULT)
add_status('nx', 'Fedora 24', 'Y', DEFAULT)
add_status('nx', 'Rawhide', 'Y', DEFAULT)

# PIE support
add_status('pie', 'RHEL 3', 'package list (since 9/2004)', DEFAULT)
add_status('pie', 'RHEL 4', 'package list', DEFAULT)
add_status('pie', 'RHEL 5', 'package list', DEFAULT)
add_status('pie', 'RHEL 6', 'package list', DEFAULT)
add_status('pie', 'RHEL 7', 'package list', DEFAULT)
add_status('pie', 'Fedora 19', 'package list', DEFAULT)
add_status('pie', 'Fedora 20', 'package list', DEFAULT)
add_status('pie', 'Fedora 21', 'package list', DEFAULT)
add_status('pie', 'Fedora 22', 'package list', DEFAULT)
add_status('pie', 'Fedora 23', 'Y', DEFAULT)
add_status('pie', 'Fedora 24', 'Y', DEFAULT)
add_status('pie', 'Rawhide', 'Y', DEFAULT)

# stack ASLR
add_status('stack-aslr', 'RHEL 3', 'Y (since 9/2004)', DEFAULT)
add_status('stack-aslr', 'RHEL 4', 'kernel', DEFAULT)
add_status('stack-aslr', 'RHEL 5', 'kernel', DEFAULT)
add_status('stack-aslr', 'RHEL 6', 'kernel', DEFAULT)
add_status('stack-aslr', 'RHEL 7', 'kernel', DEFAULT)
add_status('stack-aslr', 'Fedora 19', 'kernel', DEFAULT)
add_status('stack-aslr', 'Fedora 20', 'kernel', DEFAULT)
add_status('stack-aslr', 'Fedora 21', 'kernel', DEFAULT)
add_status('stack-aslr', 'Fedora 22', 'kernel', DEFAULT)
add_status('stack-aslr', 'Fedora 23', 'kernel', DEFAULT)
add_status('stack-aslr', 'Fedora 24', 'kernel', DEFAULT)
add_status('stack-aslr', 'Rawhide', 'kernel', DEFAULT)

# mmap ASLR
add_status('mmap-aslr', 'RHEL 3', 'kernel (since 9/2004)', DEFAULT)
add_status('mmap-aslr', 'RHEL 4', 'kernel', DEFAULT)
add_status('mmap-aslr', 'RHEL 5', 'kernel', DEFAULT)
add_status('mmap-aslr', 'RHEL 6', 'kernel', DEFAULT)
add_status('mmap-aslr', 'RHEL 7', 'kernel', DEFAULT)
add_status('mmap-aslr', 'Fedora 19', 'kernel', DEFAULT)
add_status('mmap-aslr', 'Fedora 20', 'kernel', DEFAULT)
add_status('mmap-aslr', 'Fedora 21', 'kernel', DEFAULT)
add_status('mmap-aslr', 'Fedora 22', 'kernel', DEFAULT)
add_status('mmap-aslr', 'Fedora 23', 'kernel', DEFAULT)
add_status('mmap-aslr', 'Fedora 24', 'kernel', DEFAULT)
add_status('mmap-aslr', 'Rawhide', 'kernel', DEFAULT)

# exec-aslr
add_status('exec-aslr', 'RHEL 3', '(since 9/2004)', DEFAULT)
add_status('exec-aslr', 'RHEL 4', 'Y', DEFAULT)
add_status('exec-aslr', 'RHEL 5', 'y', DEFAULT)
add_status('exec-aslr', 'RHEL 6', 'Y', DEFAULT)
add_status('exec-aslr', 'RHEL 7', 'Y', DEFAULT)
add_status('exec-aslr', 'Fedora 19', 'Y', DEFAULT)
add_status('exec-aslr', 'Fedora 20', 'Y', DEFAULT)
add_status('exec-aslr', 'Fedora 21', 'Y', DEFAULT)
add_status('exec-aslr', 'Fedora 22', 'Y', DEFAULT)
add_status('exec-aslr', 'Fedora 23', 'Y', DEFAULT)
add_status('exec-aslr', 'Fedora 24', 'Y', DEFAULT)
add_status('exec-aslr', 'Rawhide', 'Y', DEFAULT)

# vDSO ASLR
add_status('vdso-aslr', 'RHEL 3', 'no vDSO', DEFAULT)
add_status('vdso-aslr', 'RHEL 4', 'kernel', DEFAULT)
add_status('vdso-aslr', 'RHEL 5', 'kernel', DEFAULT)
add_status('vdso-aslr', 'RHEL 6', 'kernel', DEFAULT)
add_status('vdso-aslr', 'RHEL 7', 'kernel', DEFAULT)
add_status('vdso-aslr', 'Fedora 19', 'kernel', DEFAULT)
add_status('vdso-aslr', 'Fedora 20', 'kernel', DEFAULT)
add_status('vdso-aslr', 'Fedora 21', 'kernel', DEFAULT)
add_status('vdso-aslr', 'Fedora 22', 'kernel', DEFAULT)
add_status('vdso-aslr', 'Fedora 23', 'kernel', DEFAULT)
add_status('vdso-aslr', 'Fedora 24', 'kernel', DEFAULT)
add_status('vdso-aslr', 'Rawhide', 'kernel', DEFAULT)

# brk-aslr
add_status('brk-aslr', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('brk-aslr', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('brk-aslr', 'RHEL 5', '?', UNIMPLEMENTED)
add_status('brk-aslr', 'RHEL 6', 'Y', DEFAULT)
add_status('brk-aslr', 'RHEL 7', 'Y', DEFAULT)
add_status('brk-aslr', 'Fedora 19', 'Y', DEFAULT)
add_status('brk-aslr', 'Fedora 20', 'Y', DEFAULT)
add_status('brk-aslr', 'Fedora 21', 'Y', DEFAULT)
add_status('brk-aslr', 'Fedora 22', 'Y', DEFAULT)
add_status('brk-aslr', 'Fedora 23', 'Y', DEFAULT)
add_status('brk-aslr', 'Fedora 24', 'Y', DEFAULT)
add_status('brk-aslr', 'Rawhide', 'Y', DEFAULT)

# null-mmap
add_status('null-mmap', 'RHEL 3', 'Y (since 11/2009)', DEFAULT)
add_status('null-mmap', 'RHEL 4', 'Y (since 9/2009)', DEFAULT)
add_status('null-mmap', 'RHEL 5', 'Y (since 5/2008)', DEFAULT)
add_status('null-mmap', 'RHEL 6', 'Y', DEFAULT)
add_status('null-mmap', 'RHEL 7', 'Y', DEFAULT)
add_status('null-mmap', 'Fedora 19', 'Y', DEFAULT)
add_status('null-mmap', 'Fedora 20', 'Y', DEFAULT)
add_status('null-mmap', 'Fedora 21', 'Y', DEFAULT)
add_status('null-mmap', 'Fedora 22', 'Y', DEFAULT)
add_status('null-mmap', 'Fedora 23', 'Y', DEFAULT)
add_status('null-mmap', 'Fedora 24', 'Y', DEFAULT)
add_status('null-mmap', 'Rawhide', 'Y', DEFAULT)

# block-modules
add_status('block-modules', 'RHEL 3', 'Y', DEFAULT)
add_status('block-modules', 'RHEL 4', 'Y', DEFAULT)
add_status('block-modules', 'RHEL 5', 'Y', DEFAULT)
add_status('block-modules', 'RHEL 6', 'Y', DEFAULT)
add_status('block-modules', 'RHEL 7', 'Y', DEFAULT)
add_status('block-modules', 'Fedora 19', 'Y', DEFAULT)
add_status('block-modules', 'Fedora 20', 'Y', DEFAULT)
add_status('block-modules', 'Fedora 21', 'Y', DEFAULT)
add_status('block-modules', 'Fedora 22', 'Y', DEFAULT)
add_status('block-modules', 'Fedora 23', 'Y', DEFAULT)
add_status('block-modules', 'Fedora 24', 'Y', DEFAULT)
add_status('block-modules', 'Rawhide', 'Y', DEFAULT)

# dev-kmem
add_status('dev-kmem', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('dev-kmem', 'RHEL 4', 'Y', DEFAULT)
add_status('dev-kmem', 'RHEL 5', 'Y', DEFAULT)
add_status('dev-kmem', 'RHEL 6', 'Y', DEFAULT)
add_status('dev-kmem', 'RHEL 7', 'Y', DEFAULT)
add_status('dev-kmem', 'Fedora 19', 'Y', DEFAULT)
add_status('dev-kmem', 'Fedora 20', 'Y', DEFAULT)
add_status('dev-kmem', 'Fedora 21', 'Y', DEFAULT)
add_status('dev-kmem', 'Fedora 22', 'Y', DEFAULT)
add_status('dev-kmem', 'Fedora 23', 'Y', DEFAULT)
add_status('dev-kmem', 'Fedora 24', 'Y', DEFAULT)
add_status('dev-kmem', 'Rawhide', 'Y', DEFAULT)

# selinux
add_status('selinux', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('selinux', 'RHEL 4', 'Y', DEFAULT)
add_status('selinux', 'RHEL 5', 'Y', DEFAULT)
add_status('selinux', 'RHEL 6', 'Y', DEFAULT)
add_status('selinux', 'RHEL 7', 'Y', DEFAULT)
add_status('selinux', 'Fedora 19', 'Y', DEFAULT)
add_status('selinux', 'Fedora 20', 'Y', DEFAULT)
add_status('selinux', 'Fedora 21', 'Y', DEFAULT)
add_status('selinux', 'Fedora 22', 'Y', DEFAULT)
add_status('selinux', 'Fedora 23', 'Y', DEFAULT)
add_status('selinux', 'Fedora 24', 'Y', DEFAULT)
add_status('selinux', 'Rawhide', 'Y', DEFAULT)

# kernel-protect-rodata
add_status('kernel-protect-rodata', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('kernel-protect-rodata', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('kernel-protect-rodata', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('kernel-protect-rodata', 'RHEL 6', 'Y', DEFAULT)
add_status('kernel-protect-rodata', 'RHEL 7', 'Y', DEFAULT)
add_status('kernel-protect-rodata', 'Fedora 19', 'Y', DEFAULT)
add_status('kernel-protect-rodata', 'Fedora 20', 'Y', DEFAULT)
add_status('kernel-protect-rodata', 'Fedora 21', 'Y', DEFAULT)
add_status('kernel-protect-rodata', 'Fedora 22', 'Y', DEFAULT)
add_status('kernel-protect-rodata', 'Fedora 23', 'Y', DEFAULT)
add_status('kernel-protect-rodata', 'Fedora 24', 'Y', DEFAULT)
add_status('kernel-protect-rodata', 'Rawhide', 'Y', DEFAULT)

# seccomp-filter
add_status('seccomp-filter', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('seccomp-filter', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('seccomp-filter', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('seccomp-filter', 'RHEL 6', '?', UNIMPLEMENTED)
add_status('seccomp-filter', 'RHEL 7', 'Y', AVAILABLE)
add_status('seccomp-filter', 'Fedora 19', 'Y', AVAILABLE)
add_status('seccomp-filter', 'Fedora 20', 'Y', AVAILABLE)
add_status('seccomp-filter', 'Fedora 21', 'Y', AVAILABLE)
add_status('seccomp-filter', 'Fedora 22', 'Y', AVAILABLE)
add_status('seccomp-filter', 'Fedora 23', 'Y', AVAILABLE)
add_status('seccomp-filter', 'Fedora 24', 'Y', AVAILABLE)
add_status('seccomp-filter', 'Rawhide', 'Y', AVAILABLE)

# SELinuxModuleLoading
add_status('SELinuxModuleLoading', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('SELinuxModuleLoading', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('SELinuxModuleLoading', 'RHEL 5', '?', UNIMPLEMENTED)
add_status('SELinuxModuleLoading', 'RHEL 6', '?', UNIMPLEMENTED)
add_status('SELinuxModuleLoading', 'RHEL 7', 'Y', AVAILABLE)
add_status('SELinuxModuleLoading', 'Fedora 19', 'Y', AVAILABLE)
add_status('SELinuxModuleLoading', 'Fedora 20', 'Y', AVAILABLE)
add_status('SELinuxModuleLoading', 'Fedora 21', 'Y', AVAILABLE)
add_status('SELinuxModuleLoading', 'Fedora 22', 'Y', AVAILABLE)
add_status('SELinuxModuleLoading', 'Fedora 23', 'Y', AVAILABLE)
add_status('SELinuxModuleLoading', 'Fedora 24', 'Y', AVAILABLE)
add_status('SELinuxModuleLoading', 'Rawhide', 'Y', AVAILABLE)

# hashing
add_status('hashing', 'RHEL 3', 'md5crypt', DEFAULT)
add_status('hashing', 'RHEL 4', 'md5crypt', DEFAULT)
add_status('hashing', 'RHEL 5', 'md5crypt', DEFAULT)
add_status('hashing', 'RHEL 6', 'sha512crypt', DEFAULT)
add_status('hashing', 'RHEL 7', 'sha512crypt', DEFAULT)
add_status('hashing', 'Fedora 19', 'sha512crypt', DEFAULT)
add_status('hashing', 'Fedora 20', 'sha512crypt', DEFAULT)
add_status('hashing', 'Fedora 21', 'sha512crypt', DEFAULT)
add_status('hashing', 'Fedora 22', 'sha512crypt', DEFAULT)
add_status('hashing', 'Fedora 23', 'sha512crypt', DEFAULT)
add_status('hashing', 'Fedora 24', 'sha512crypt', DEFAULT)
add_status('hashing', 'Rawhide', 'sha512crypt', DEFAULT)

# eCryptfs
add_status('ecryptfs', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('ecryptfs', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('ecryptfs', 'RHEL 5', 'Y', AVAILABLE)
add_status('ecryptfs', 'RHEL 6', 'Y', AVAILABLE)
add_status('ecryptfs', 'RHEL 7', 'Y', AVAILABLE)
add_status('ecryptfs', 'Fedora 19', 'Optional Package', AVAILABLE)
add_status('ecryptfs', 'Fedora 20', 'Optional Package', AVAILABLE)
add_status('ecryptfs', 'Fedora 21', 'Optional Package', AVAILABLE)
add_status('ecryptfs', 'Fedora 22', 'Optional Package', AVAILABLE)
add_status('ecryptfs', 'Fedora 23', 'Optional Package', AVAILABLE)
add_status('ecryptfs', 'Fedora 24', 'Optional Package', AVAILABLE)
add_status('ecryptfs', 'Rawhide', 'Optional Package', AVAILABLE)

# fscaps
add_status('fscaps', 'RHEL 3', '--', UNIMPLEMENTED)
add_status('fscaps', 'RHEL 4', 'kernel', AVAILABLE)
add_status('fscaps', 'RHEL 5', 'kernel', AVAILABLE)
add_status('fscaps', 'RHEL 6', 'kernel', AVAILABLE)
add_status('fscaps', 'RHEL 7', 'kernel', AVAILABLE)
add_status('fscaps', 'Fedora 19', 'kernel', AVAILABLE)
add_status('fscaps', 'Fedora 20', 'kernel', AVAILABLE)
add_status('fscaps', 'Fedora 21', 'kernel', AVAILABLE)
add_status('fscaps', 'Fedora 22', 'kernel', AVAILABLE)
add_status('fscaps', 'Fedora 23', 'kernel', AVAILABLE)
add_status('fscaps', 'Fedora 24', 'kernel', AVAILABLE)
add_status('fscaps', 'Rawhide', 'kernel', AVAILABLE)

# dev-mem
add_status('dev-mem', 'RHEL 3', '--', UNIMPLEMENTED)
add_status('dev-mem', 'RHEL 4', 'kernel', DEFAULT)
add_status('dev-mem', 'RHEL 5', 'kernel', DEFAULT)
add_status('dev-mem', 'RHEL 6', 'kernel', DEFAULT)
add_status('dev-mem', 'RHEL 7', 'kernel', DEFAULT)
add_status('dev-mem', 'Fedora 19', 'kernel', DEFAULT)
add_status('dev-mem', 'Fedora 20', 'kernel', DEFAULT)
add_status('dev-mem', 'Fedora 21', 'kernel', DEFAULT)
add_status('dev-mem', 'Fedora 22', 'kernel', DEFAULT)
add_status('dev-mem', 'Fedora 23', 'kernel', DEFAULT)
add_status('dev-mem', 'Fedora 24', 'kernel', DEFAULT)
add_status('dev-mem', 'Rawhide', 'kernel', DEFAULT)

# encrypted-lvm
add_status('encrypted-lvm', 'RHEL 3', '?', UNIMPLEMENTED)
add_status('encrypted-lvm', 'RHEL 4', '?', UNIMPLEMENTED)
add_status('encrypted-lvm', 'RHEL 5', 'Y', AVAILABLE)
add_status('encrypted-lvm', 'RHEL 6', 'Standard Installer', AVAILABLE)
add_status('encrypted-lvm', 'RHEL 7', 'Standard Installer', AVAILABLE)
add_status('encrypted-lvm', 'Fedora 19', 'Standard Installer', AVAILABLE)
add_status('encrypted-lvm', 'Fedora 20', 'Standard Installer', AVAILABLE)
add_status('encrypted-lvm', 'Fedora 21', 'Standard Installer', AVAILABLE)
add_status('encrypted-lvm', 'Fedora 22', 'Standard Installer', AVAILABLE)
add_status('encrypted-lvm', 'Fedora 23', 'Standard Installer', AVAILABLE)
add_status('encrypted-lvm', 'Fedora 24', 'Standard Installer', AVAILABLE)
add_status('encrypted-lvm', 'Rawhide', 'Standard Installer', AVAILABLE)

# kernel-stack-protector
add_status('kernel-stack-protector', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('kernel-stack-protector', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('kernel-stack-protector', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('kernel-stack-protector', 'RHEL 6', 'Y', DEFAULT)
add_status('kernel-stack-protector', 'RHEL 7', 'Y', DEFAULT)
add_status('kernel-stack-protector', 'Fedora 19', 'Y', DEFAULT)
add_status('kernel-stack-protector', 'Fedora 20', 'Y', DEFAULT)
add_status('kernel-stack-protector', 'Fedora 21', 'Y', DEFAULT)
add_status('kernel-stack-protector', 'Fedora 22', 'Y', DEFAULT)
add_status('kernel-stack-protector', 'Fedora 23', 'Y', DEFAULT)
add_status('kernel-stack-protector', 'Fedora 24', 'Y', DEFAULT)
add_status('kernel-stack-protector', 'Rawhide', 'Y', DEFAULT)

# sVirt labelling
add_status('sVirt', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('sVirt', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('sVirt', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('sVirt', 'RHEL 6', 'Y', DEFAULT)
add_status('sVirt', 'RHEL 7', 'Y', DEFAULT)
add_status('sVirt', 'Fedora 19', 'Y', DEFAULT)
add_status('sVirt', 'Fedora 20', 'Y', DEFAULT)
add_status('sVirt', 'Fedora 21', 'Y', DEFAULT)
add_status('sVirt', 'Fedora 22', 'Y', DEFAULT)
add_status('sVirt', 'Fedora 23', 'Y', DEFAULT)
add_status('sVirt', 'Fedora 24', 'Y', DEFAULT)
add_status('sVirt', 'Rawhide', 'Y', DEFAULT)

# SELinuxConfineUsers
add_status('SELinuxConfineUsers', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('SELinuxConfineUsers', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('SELinuxConfineUsers', 'RHEL 5', 'Y', AVAILABLE)
add_status('SELinuxConfineUsers', 'RHEL 6', 'Y', DEFAULT)
add_status('SELinuxConfineUsers', 'RHEL 7', 'Y', DEFAULT)
add_status('SELinuxConfineUsers', 'Fedora 19', 'Y', DEFAULT)
add_status('SELinuxConfineUsers', 'Fedora 20', 'Y', DEFAULT)
add_status('SELinuxConfineUsers', 'Fedora 21', 'Y', DEFAULT)
add_status('SELinuxConfineUsers', 'Fedora 22', 'Y', DEFAULT)
add_status('SELinuxConfineUsers', 'Fedora 23', 'Y', DEFAULT)
add_status('SELinuxConfineUsers', 'Fedora 24', 'Y', DEFAULT)
add_status('SELinuxConfineUsers', 'Rawhide', 'Y', DEFAULT)

# SELinuxSandbox
add_status('SELinuxSandbox', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('SELinuxSandbox', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('SELinuxSandbox', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('SELinuxSandbox', 'RHEL 6', 'Y', DEFAULT)
add_status('SELinuxSandbox', 'RHEL 7', 'Y', DEFAULT)
add_status('SELinuxSandbox', 'Fedora 19', 'Y', DEFAULT)
add_status('SELinuxSandbox', 'Fedora 20', 'Y', DEFAULT)
add_status('SELinuxSandbox', 'Fedora 21', 'Y', DEFAULT)
add_status('SELinuxSandbox', 'Fedora 22', 'Y', DEFAULT)
add_status('SELinuxSandbox', 'Fedora 23', 'Y', DEFAULT)
add_status('SELinuxSandbox', 'Fedora 24', 'Y', DEFAULT)
add_status('SELinuxSandbox', 'Rawhide', 'Y', DEFAULT)

# XACE
add_status('XACE', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('XACE', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('XACE', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('XACE', 'RHEL 6', 'Y', AVAILABLE)
add_status('XACE', 'RHEL 7', 'Y', AVAILABLE)
add_status('XACE', 'Fedora 19', 'Y', AVAILABLE)
add_status('XACE', 'Fedora 20', 'Y', AVAILABLE)
add_status('XACE', 'Fedora 21', 'Y', AVAILABLE)
add_status('XACE', 'Fedora 22', 'Y', AVAILABLE)
add_status('XACE', 'Fedora 23', 'Y', AVAILABLE)
add_status('XACE', 'Fedora 24', 'Y', AVAILABLE)
add_status('XACE', 'Rawhide', 'Y', AVAILABLE)

# RELRO
add_status('relro', 'RHEL 3', '--', UNIMPLEMENTED)
add_status('relro', 'RHEL 4', '--', UNIMPLEMENTED)
add_status('relro', 'RHEL 5', '--', UNIMPLEMENTED)
add_status('relro', 'RHEL 6', '--', UNIMPLEMENTED)
add_status('relro', 'RHEL 7', 'gcc patch', DEFAULT)
add_status('relro', 'Fedora 19', 'gcc patch', DEFAULT)
add_status('relro', 'Fedora 20', 'gcc patch', DEFAULT)
add_status('relro', 'Fedora 21', 'gcc patch', DEFAULT)
add_status('relro', 'Fedora 22', 'gcc patch', DEFAULT)
add_status('relro', 'Fedora 23', 'Y', DEFAULT)
add_status('relro', 'Fedora 24', 'Y', DEFAULT)
add_status('relro', 'Rawhide', 'Y', DEFAULT)

# proc-maps
add_status('proc-maps', 'RHEL 3', '--', UNIMPLEMENTED)
add_status('proc-maps', 'RHEL 4', '--', UNIMPLEMENTED)
add_status('proc-maps', 'RHEL 5', '--', UNIMPLEMENTED)
add_status('proc-maps', 'RHEL 6', '--', UNIMPLEMENTED)
add_status('proc-maps', 'RHEL 7', 'kernel & sysctl', DEFAULT)
add_status('proc-maps', 'Fedora 19', 'kernel & sysctl', DEFAULT)
add_status('proc-maps', 'Fedora 20', 'kernel & sysctl', DEFAULT)
add_status('proc-maps', 'Fedora 21', 'kernel & sysctl', DEFAULT)
add_status('proc-maps', 'Fedora 22', 'kernel & sysctl', DEFAULT)
add_status('proc-maps', 'Fedora 23', 'kernel & sysctl', DEFAULT)
add_status('proc-maps', 'Fedora 24', 'kernel & sysctl', DEFAULT)
add_status('proc-maps', 'Rawhide', 'kernel & sysctl', DEFAULT)

# dev-mem
add_status('dev-mem', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('dev-mem', 'RHEL 4', 'Y', DEFAULT)
add_status('dev-mem', 'RHEL 5', 'Y', DEFAULT)
add_status('dev-mem', 'RHEL 6', 'Y', DEFAULT)
add_status('dev-mem', 'RHEL 7', 'Y', DEFAULT)
add_status('dev-mem', 'Fedora 19', 'Y', DEFAULT)
add_status('dev-mem', 'Fedora 20', 'Y', DEFAULT)
add_status('dev-mem', 'Fedora 21', 'Y', DEFAULT)
add_status('dev-mem', 'Fedora 22', 'Y', DEFAULT)
add_status('dev-mem', 'Fedora 23', 'Y', DEFAULT)
add_status('dev-mem', 'Fedora 24', 'Y', DEFAULT)
add_status('dev-mem', 'Rawhide', 'Y', DEFAULT)

# seccomp
add_status('seccomp', 'RHEL 3', '--', UNIMPLEMENTED)
add_status('seccomp', 'RHEL 4', '--', UNIMPLEMENTED)
add_status('seccomp', 'RHEL 5', '--', UNIMPLEMENTED)
add_status('seccomp', 'RHEL 6', '--', UNIMPLEMENTED)
add_status('seccomp', 'RHEL 7', 'kernel', AVAILABLE)
add_status('seccomp', 'Fedora 19', 'kernel', AVAILABLE)
add_status('seccomp', 'Fedora 20', 'kernel', AVAILABLE)
add_status('seccomp', 'Fedora 21', 'kernel', AVAILABLE)
add_status('seccomp', 'Fedora 22', 'kernel', AVAILABLE)
add_status('seccomp', 'Fedora 23', 'kernel', AVAILABLE)
add_status('seccomp', 'Fedora 24', 'kernel', AVAILABLE)
add_status('seccomp', 'rawhide', 'kernel', AVAILABLE)

# SYN cookies
add_status('syn-cookies', 'RHEL 3', '?', AVAILABLE)
add_status('syn-cookies', 'RHEL 4', 'kernel', AVAILABLE)
add_status('syn-cookies', 'RHEL 5', 'kernel', DEFAULT)
add_status('syn-cookies', 'RHEL 6', 'kernel', DEFAULT)
add_status('syn-cookies', 'RHEL 7', 'kernel', DEFAULT)
add_status('syn-cookies', 'Fedora 19', 'kernel', DEFAULT)
add_status('syn-cookies', 'Fedora 20', 'kernel', DEFAULT)
add_status('syn-cookies', 'Fedora 21', 'kernel', DEFAULT)
add_status('syn-cookies', 'Fedora 22', 'kernel', DEFAULT)
add_status('syn-cookies', 'Fedora 23', 'kernel', DEFAULT)
add_status('syn-cookies', 'Fedora 24', 'kernel', DEFAULT)
add_status('syn-cookies', 'Rawhide', 'kernel', DEFAULT)

# SELinuxDenyPtrace
add_status('SELinuxDenyPtrace', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('SELinuxDenyPtrace', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('SELinuxDenyPtrace', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('SELinuxDenyPtrace', 'RHEL 6', 'N', UNIMPLEMENTED)
add_status('SELinuxDenyPtrace', 'RHEL 7', 'Y', AVAILABLE)
add_status('SELinuxDenyPtrace', 'Fedora 19', 'Y', AVAILABLE)
add_status('SELinuxDenyPtrace', 'Fedora 20', 'Y', AVAILABLE)
add_status('SELinuxDenyPtrace', 'Fedora 21', 'Y', AVAILABLE)
add_status('SELinuxDenyPtrace', 'Fedora 22', 'Y', AVAILABLE)
add_status('SELinuxDenyPtrace', 'Fedora 23', 'Y', AVAILABLE)
add_status('SELinuxDenyPtrace', 'Fedora 24', 'Y', AVAILABLE)
add_status('SELinuxDenyPtrace', 'rawhide', 'Y', AVAILABLE)

# selinux-targeted
add_status('selinux-targeted', 'RHEL 3',  'N', UNIMPLEMENTED)
add_status('selinux-targeted', 'RHEL 4',  'Y', DEFAULT)
add_status('selinux-targeted', 'RHEL 5',  'Y', DEFAULT)
add_status('selinux-targeted', 'RHEL 6',  'Y', DEFAULT)
add_status('selinux-targeted', 'RHEL 7',  'Y', DEFAULT)
add_status('selinux-targeted', 'Fedora 19', 'Y', DEFAULT)
add_status('selinux-targeted', 'Fedora 20', 'Y', DEFAULT)
add_status('selinux-targeted', 'Fedora 21', 'Y', DEFAULT)
add_status('selinux-targeted', 'Fedora 22', 'Y', DEFAULT)
add_status('selinux-targeted', 'Fedora 23', 'Y', DEFAULT)
add_status('selinux-targeted', 'Fedora 24', 'Y', DEFAULT)
add_status('selinux-targeted', 'Rawhide',   'Y', DEFAULT)

# heap-protector
add_status('heap-protector', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('heap-protector', 'RHEL 4', 'glibc', DEFAULT)
add_status('heap-protector', 'RHEL 5', 'glibc', DEFAULT)
add_status('heap-protector', 'RHEL 6', 'glibc', DEFAULT)
add_status('heap-protector', 'RHEL 7', 'glibc', DEFAULT)
add_status('heap-protector', 'Fedora 19', 'glibc', DEFAULT)
add_status('heap-protector', 'Fedora 20', 'glibc', DEFAULT)
add_status('heap-protector', 'Fedora 21', 'glibc', DEFAULT)
add_status('heap-protector', 'Fedora 22', 'glibc', DEFAULT)
add_status('heap-protector', 'Fedora 23', 'glibc', DEFAULT)
add_status('heap-protector', 'Fedora 24', 'glibc', DEFAULT)
add_status('heap-protector', 'Rawhide', 'glibc', DEFAULT)

# FORTIFY_SOURCE
add_status('fortify-source', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('fortify-source', 'RHEL 4', 'Y', AVAILABLE)
add_status('fortify-source', 'RHEL 5', 'Y', DEFAULT)
add_status('fortify-source', 'RHEL 6', 'Y', DEFAULT)
add_status('fortify-source', 'RHEL 7', 'Y', DEFAULT)
add_status('fortify-source', 'Fedora 19', 'Y', DEFAULT)
add_status('fortify-source', 'Fedora 20', 'Y', DEFAULT)
add_status('fortify-source', 'Fedora 21', 'Y', DEFAULT)
add_status('fortify-source', 'Fedora 22', 'Y', DEFAULT)
add_status('fortify-source', 'Fedora 23', 'Y', DEFAULT)
add_status('fortify-source', 'Fedora 24', 'Y', DEFAULT)
add_status('fortify-source', 'Rawhide', 'Y', DEFAULT)

# bindnow (BIND_NOW)
add_status('bindnow', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('bindnow', 'RHEL 4', '?', AVAILABLE)
add_status('bindnow', 'RHEL 5', 'package list', DEFAULT)
add_status('bindnow', 'RHEL 6', 'package list', DEFAULT)
add_status('bindnow', 'RHEL 7', 'package list', DEFAULT)
add_status('bindnow', 'Fedora 19', 'package list', DEFAULT)
add_status('bindnow', 'Fedora 20', 'package list', DEFAULT)
add_status('bindnow', 'Fedora 21', 'package list', DEFAULT)
add_status('bindnow', 'Fedora 22', 'package list', DEFAULT)
add_status('bindnow', 'Fedora 23', 'Y', DEFAULT)
add_status('bindnow', 'Fedora 24', 'Y', DEFAULT)
add_status('bindnow', 'Rawhide', 'Y', DEFAULT)

# stack-protector
add_status('stack-protector', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('stack-protector', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('stack-protector', 'RHEL 5', 'Y', DEFAULT)
add_status('stack-protector', 'RHEL 6', 'Y', DEFAULT)
add_status('stack-protector', 'RHEL 7', 'Y', DEFAULT)
add_status('stack-protector', 'Fedora 19', 'Y', DEFAULT)
add_status('stack-protector', 'Fedora 20', 'Y', DEFAULT)
add_status('stack-protector', 'Fedora 21', 'Y', DEFAULT)
add_status('stack-protector', 'Fedora 22', 'Y', DEFAULT)
add_status('stack-protector', 'Fedora 23', 'Y', DEFAULT)
add_status('stack-protector', 'Fedora 24', 'Y', DEFAULT)
add_status('stack-protector', 'Rawhide', 'Y', DEFAULT)

# selinux_EMP
add_status('selinux_EMP', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('selinux_EMP', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('selinux_EMP', 'RHEL 5', 'Y', DEFAULT)
add_status('selinux_EMP', 'RHEL 6', 'Y', DEFAULT)
add_status('selinux_EMP', 'RHEL 7', 'Y', DEFAULT)
add_status('selinux_EMP', 'Fedora 19', 'Y', DEFAULT)
add_status('selinux_EMP', 'Fedora 20', 'Y', DEFAULT)
add_status('selinux_EMP', 'Fedora 21', 'Y', DEFAULT)
add_status('selinux_EMP', 'Fedora 22', 'Y', DEFAULT)
add_status('selinux_EMP', 'Fedora 23', 'Y', DEFAULT)
add_status('selinux_EMP', 'Fedora 24', 'Y', DEFAULT)
add_status('selinux_EMP', 'Rawhide', 'Y', DEFAULT)

# pointer-obfuscation
add_status('pointer-obfuscation', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('pointer-obfuscation', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('pointer-obfuscation', 'RHEL 5', 'Y', DEFAULT)
add_status('pointer-obfuscation', 'RHEL 6', 'Y', DEFAULT)
add_status('pointer-obfuscation', 'RHEL 7', 'Y', DEFAULT)
add_status('pointer-obfuscation', 'Fedora 19', 'glibc', DEFAULT)
add_status('pointer-obfuscation', 'Fedora 20', 'glibc', DEFAULT)
add_status('pointer-obfuscation', 'Fedora 21', 'glibc', DEFAULT)
add_status('pointer-obfuscation', 'Fedora 22', 'glibc', DEFAULT)
add_status('pointer-obfuscation', 'Fedora 23', 'glibc', DEFAULT)
add_status('pointer-obfuscation', 'Fedora 24', 'glibc', DEFAULT)
add_status('pointer-obfuscation', 'Rawhide', 'glibc', DEFAULT)

# symlink protections
add_status('symlink', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('symlink', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('symlink', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('symlink', 'RHEL 6', 'N', UNIMPLEMENTED)
add_status('symlink', 'RHEL 7', 'Y', AVAILABLE)
add_status('symlink', 'Fedora 19', 'Y', AVAILABLE)
add_status('symlink', 'Fedora 20', 'Y', AVAILABLE)
add_status('symlink', 'Fedora 21', 'Y', AVAILABLE)
add_status('symlink', 'Fedora 22', 'Y', AVAILABLE)
add_status('symlink', 'Fedora 23', 'Y', AVAILABLE)
add_status('symlink', 'Fedora 24', 'Y', AVAILABLE)
add_status('symlink', 'Rawhide', 'Y', AVAILABLE)

# hardlink protections
add_status('hardlink', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('hardlink', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('hardlink', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('hardlink', 'RHEL 6', 'N', UNIMPLEMENTED)
add_status('hardlink', 'RHEL 7', 'Y', AVAILABLE)
add_status('hardlink', 'Fedora 19', 'Y', AVAILABLE)
add_status('hardlink', 'Fedora 20', 'Y', AVAILABLE)
add_status('hardlink', 'Fedora 21', 'Y', AVAILABLE)
add_status('hardlink', 'Fedora 22', 'Y', AVAILABLE)
add_status('hardlink', 'Fedora 23', 'Y', AVAILABLE)
add_status('hardlink', 'Fedora 24', 'Y', AVAILABLE)
add_status('hardlink', 'Rawhide', 'Y', AVAILABLE)

# namespaces protections
add_status('namespaces', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('namespaces', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('namespaces', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('namespaces', 'RHEL 6', 'N', UNIMPLEMENTED)
add_status('namespaces', 'RHEL 7', 'N', UNIMPLEMENTED)
add_status('namespaces', 'Fedora 19', 'N', UNIMPLEMENTED)
add_status('namespaces', 'Fedora 20', 'N', UNIMPLEMENTED)
add_status('namespaces', 'Fedora 21', 'N', UNIMPLEMENTED)
add_status('namespaces', 'Fedora 22', 'N', UNIMPLEMENTED)
add_status('namespaces', 'Fedora 23', 'N', UNIMPLEMENTED)
add_status('namespaces', 'Fedora 24', 'N', UNIMPLEMENTED)
add_status('namespaces', 'Rawhide', 'N', UNIMPLEMENTED)

# systemd_namespace protections
add_status('systemd_namespace', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('systemd_namespace', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('systemd_namespace', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('systemd_namespace', 'RHEL 6', 'N', UNIMPLEMENTED)
add_status('systemd_namespace', 'RHEL 7', 'Y', AVAILABLE)
add_status('systemd_namespace', 'Fedora 19', 'Y', AVAILABLE)
add_status('systemd_namespace', 'Fedora 20', 'Y', AVAILABLE)
add_status('systemd_namespace', 'Fedora 21', 'Y', AVAILABLE)
add_status('systemd_namespace', 'Fedora 22', 'Y', AVAILABLE)
add_status('systemd_namespace', 'Fedora 23', 'Y', AVAILABLE)
add_status('systemd_namespace', 'Fedora 24', 'Y', AVAILABLE)
add_status('systemd_namespace', 'Rawhide', 'Y', AVAILABLE)

# systemd_namespace protections
add_status('polyinstantiate', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('polyinstantiate', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('polyinstantiate', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('polyinstantiate', 'RHEL 6', 'Y', AVAILABLE)
add_status('polyinstantiate', 'RHEL 7', 'Y', AVAILABLE)
add_status('polyinstantiate', 'Fedora 19', 'Y', AVAILABLE)
add_status('polyinstantiate', 'Fedora 20', 'Y', AVAILABLE)
add_status('polyinstantiate', 'Fedora 21', 'Y', AVAILABLE)
add_status('polyinstantiate', 'Fedora 22', 'Y', AVAILABLE)
add_status('polyinstantiate', 'Fedora 23', 'Y', AVAILABLE)
add_status('polyinstantiate', 'Fedora 24', 'Y', AVAILABLE)
add_status('polyinstantiate', 'Rawhide', 'Y', AVAILABLE)

# secure boot
add_status('secureboot', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('secureboot', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('secureboot', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('secureboot', 'RHEL 6', 'N', UNIMPLEMENTED)
add_status('secureboot', 'RHEL 7', 'Y', AVAILABLE)
add_status('secureboot', 'Fedora 19', 'Y', AVAILABLE)
add_status('secureboot', 'Fedora 20', 'Y', AVAILABLE)
add_status('secureboot', 'Fedora 21', 'Y', AVAILABLE)
add_status('secureboot', 'Fedora 22', 'Y', AVAILABLE)
add_status('secureboot', 'Fedora 23', 'Y', AVAILABLE)
add_status('secureboot', 'Fedora 24', 'Y', AVAILABLE)
add_status('secureboot', 'Rawhide', 'Y', AVAILABLE)

# Forward Secure Sealing
add_status('tamperproof', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('tamperproof', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('tamperproof', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('tamperproof', 'RHEL 6', 'N', UNIMPLEMENTED)
add_status('tamperproof', 'RHEL 7', 'Y', AVAILABLE)
add_status('tamperproof', 'Fedora 19', 'Y', AVAILABLE)
add_status('tamperproof', 'Fedora 20', 'Y', AVAILABLE)
add_status('tamperproof', 'Fedora 21', 'Y', AVAILABLE)
add_status('tamperproof', 'Fedora 22', 'Y', AVAILABLE)
add_status('tamperproof', 'Fedora 23', 'Y', AVAILABLE)
add_status('tamperproof', 'Fedora 24', 'Y', AVAILABLE)
add_status('tamperproof', 'Rawhide', 'Y', AVAILABLE)

# Overflow checking in operator new[]
add_status('newoperator', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('newoperator', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('newoperator', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('newoperator', 'RHEL 6', 'N', UNIMPLEMENTED)
add_status('newoperator', 'RHEL 7', 'Y', AVAILABLE)
add_status('newoperator', 'Fedora 19', 'Y', AVAILABLE)
add_status('newoperator', 'Fedora 20', 'Y', AVAILABLE)
add_status('newoperator', 'Fedora 21', 'Y', AVAILABLE)
add_status('newoperator', 'Fedora 22', 'Y', AVAILABLE)
add_status('newoperator', 'Fedora 23', 'Y', AVAILABLE)
add_status('newoperator', 'Fedora 24', 'Y', AVAILABLE)
add_status('newoperator', 'Rawhide', 'Y', AVAILABLE)

# symlink
add_status('symlink', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('symlink', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('symlink', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('symlink', 'RHEL 6', 'N', UNIMPLEMENTED)
add_status('symlink', 'RHEL 7', 'Y', AVAILABLE)
add_status('symlink', 'Fedora 19', 'kernel', AVAILABLE)
add_status('symlink', 'Fedora 20', 'kernel', AVAILABLE)
add_status('symlink', 'Fedora 21', 'kernel', AVAILABLE)
add_status('symlink', 'Fedora 22', 'kernel', AVAILABLE)
add_status('symlink', 'Fedora 23', 'kernel', AVAILABLE)
add_status('symlink', 'Fedora 24', 'kernel', AVAILABLE)
add_status('symlink', 'Rawhide', 'kernel', AVAILABLE)

# hardlink
add_status('hardlink', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('hardlink', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('hardlink', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('hardlink', 'RHEL 6', 'N', UNIMPLEMENTED)
add_status('hardlink', 'RHEL 7', 'Y', AVAILABLE)
add_status('hardlink', 'Fedora 19', 'kernel', AVAILABLE)
add_status('hardlink', 'Fedora 20', 'kernel', AVAILABLE)
add_status('hardlink', 'Fedora 21', 'kernel', AVAILABLE)
add_status('hardlink', 'Fedora 22', 'kernel', AVAILABLE)
add_status('hardlink', 'Fedora 23', 'kernel', AVAILABLE)
add_status('hardlink', 'Fedora 24', 'kernel', AVAILABLE)
add_status('hardlink', 'Rawhide', 'kernel', AVAILABLE)

# ptrace
add_status('ptrace', 'RHEL 3', 'N', UNIMPLEMENTED)
add_status('ptrace', 'RHEL 4', 'N', UNIMPLEMENTED)
add_status('ptrace', 'RHEL 5', 'N', UNIMPLEMENTED)
add_status('ptrace', 'RHEL 6', 'N', UNIMPLEMENTED)
add_status('ptrace', 'RHEL 7', 'N', UNIMPLEMENTED)
add_status('ptrace', 'Fedora 19', 'N', UNIMPLEMENTED)
add_status('ptrace', 'Fedora 20', 'N', UNIMPLEMENTED)
add_status('ptrace', 'Fedora 21', 'N', UNIMPLEMENTED)
add_status('ptrace', 'Fedora 22', 'N', UNIMPLEMENTED)
add_status('ptrace', 'Fedora 23', 'N', UNIMPLEMENTED)
add_status('ptrace', 'Fedora 24', 'N', UNIMPLEMENTED)
add_status('ptrace', 'rawhide', 'N', UNIMPLEMENTED)

# kptr-restrict
add_status('kptr-restrict', 'RHEL 3', '--', UNIMPLEMENTED)
add_status('kptr-restrict', 'RHEL 4', '--', UNIMPLEMENTED)
add_status('kptr-restrict', 'RHEL 5', '--', UNIMPLEMENTED)
add_status('kptr-restrict', 'RHEL 6', '--', UNIMPLEMENTED)
add_status('kptr-restrict', 'RHEL 7', 'kernel', DEFAULT)
add_status('kptr-restrict', 'Fedora 19', 'kernel', DEFAULT)
add_status('kptr-restrict', 'Fedora 20', 'kernel', DEFAULT)
add_status('kptr-restrict', 'Fedora 21', 'kernel', DEFAULT)
add_status('kptr-restrict', 'Fedora 22', 'kernel', DEFAULT)
add_status('kptr-restrict', 'Fedora 23', 'kernel', DEFAULT)
add_status('kptr-restrict', 'Fedora 24', 'kernel', DEFAULT)
add_status('kptr-restrict', 'Rawhide', 'kernel', DEFAULT)

# module-ronx
add_status('module-ronx', 'RHEL 3', '--', UNIMPLEMENTED)
add_status('module-ronx', 'RHEL 4', '--', UNIMPLEMENTED)
add_status('module-ronx', 'RHEL 5', '--', UNIMPLEMENTED)
add_status('module-ronx', 'RHEL 6', '--', UNIMPLEMENTED)
add_status('module-ronx', 'RHEL 7', 'kernel', DEFAULT)
add_status('module-ronx', 'Fedora 19', 'kernel', DEFAULT)
add_status('module-ronx', 'Fedora 20', 'kernel', DEFAULT)
add_status('module-ronx', 'Fedora 21', 'kernel', DEFAULT)
add_status('module-ronx', 'Fedora 22', 'kernel', DEFAULT)
add_status('module-ronx', 'Fedora 23', 'kernel', DEFAULT)
add_status('module-ronx', 'Fedora 24', 'kernel', DEFAULT)
add_status('module-ronx', 'Rawhide', 'kernel', DEFAULT)

# blacklist rate protocols
add_status('blacklist-rare-net', 'RHEL 3', 'Y', AVAILABLE)
add_status('blacklist-rare-net', 'RHEL 4', 'Y', AVAILABLE)
add_status('blacklist-rare-net', 'RHEL 5', 'Y', AVAILABLE)
add_status('blacklist-rare-net', 'RHEL 6', 'Y', AVAILABLE)
add_status('blacklist-rare-net', 'RHEL 7', 'Y', AVAILABLE)
add_status('blacklist-rare-net', 'Fedora 19', 'Y', AVAILABLE)
add_status('blacklist-rare-net', 'Fedora 20', 'Y', AVAILABLE)
add_status('blacklist-rare-net', 'Fedora 21', 'Y', AVAILABLE)
add_status('blacklist-rare-net', 'Fedora 22', 'Y', AVAILABLE)
add_status('blacklist-rare-net', 'Fedora 23', 'Y', AVAILABLE)
add_status('blacklist-rare-net', 'Fedora 24', 'Y', AVAILABLE)
add_status('blacklist-rare-net', 'Rawhide', 'Y', AVAILABLE)

# Format Security
add_status('format-security', 'RHEL 3', '--', UNIMPLEMENTED)
add_status('format-security', 'RHEL 4', '--', UNIMPLEMENTED)
add_status('format-security', 'RHEL 5', '--', UNIMPLEMENTED)
add_status('format-security', 'RHEL 6', '--', UNIMPLEMENTED)
add_status('format-security', 'RHEL 7', '--', UNIMPLEMENTED)
add_status('format-security', 'Fedora 19', '--', UNIMPLEMENTED)
add_status('format-security', 'Fedora 20', '--', UNIMPLEMENTED)
add_status('format-security', 'Fedora 21', 'Y', DEFAULT)
add_status('format-security', 'Fedora 22', 'Y', DEFAULT)
add_status('format-security', 'Fedora 23', 'Y', DEFAULT)
add_status('format-security', 'Fedora 24', 'Y', DEFAULT)
add_status('format-security', 'Rawhide', 'Y', DEFAULT)

# crypto-policy
add_status('crypto-policy', 'RHEL 3', '--', UNIMPLEMENTED)
add_status('crypto-policy', 'RHEL 4', '--', UNIMPLEMENTED)
add_status('crypto-policy', 'RHEL 5', '--', UNIMPLEMENTED)
add_status('crypto-policy', 'RHEL 6', '--', UNIMPLEMENTED)
add_status('crypto-policy', 'RHEL 7', '--', UNIMPLEMENTED)
add_status('crypto-policy', 'Fedora 19', '--', UNIMPLEMENTED)
add_status('crypto-policy', 'Fedora 20', '--', UNIMPLEMENTED)
add_status('crypto-policy', 'Fedora 21', 'Y', DEFAULT)
add_status('crypto-policy', 'Fedora 22', 'Y', DEFAULT)
add_status('crypto-policy', 'Fedora 23', 'Y', DEFAULT)
add_status('crypto-policy', 'Fedora 24', 'Y', DEFAULT)
add_status('crypto-policy', 'Rawhide', 'Y', DEFAULT)

# Stack Protector Strong
add_status('stack-protector-strong', 'RHEL 3', '--', UNIMPLEMENTED)
add_status('stack-protector-strong', 'RHEL 4', '--', UNIMPLEMENTED)
add_status('stack-protector-strong', 'RHEL 5', '--', UNIMPLEMENTED)
add_status('stack-protector-strong', 'RHEL 6', '--', UNIMPLEMENTED)
add_status('stack-protector-strong', 'RHEL 7', '--', UNIMPLEMENTED)
add_status('stack-protector-strong', 'Fedora 19', '--', UNIMPLEMENTED)
add_status('stack-protector-strong', 'Fedora 20', 'Y', DEFAULT)
add_status('stack-protector-strong', 'Fedora 21', 'Y', DEFAULT)
add_status('stack-protector-strong', 'Fedora 22', 'Y', DEFAULT)
add_status('stack-protector-strong', 'Fedora 23', 'Y', DEFAULT)
add_status('stack-protector-strong', 'Fedora 24', 'Y', DEFAULT)
add_status('stack-protector-strong', 'Rawhide', 'Y', DEFAULT)
