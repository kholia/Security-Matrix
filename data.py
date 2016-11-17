"""Security Matrix Data"""

# Vulnerability and threat mitigation features in Fedora
# http://www.awe.com/mark/blog/20101130.html

# features[name]["short"]
# features[name]["desc"]
# features[name]["depth"]
# features[name]["matrix"]["Fedora 19"]["status"] = "policy"
# features[name]["matrix"]["Fedora 19"]["state"] = AVAILABLE

feature_list = [
    {"name": "configuration", "short": "Configuration",
     "depth": 0,
     "section": 1, "desc": ""},

    {"name": "firewall", "short": "Configurable Firewall",
      "depth": 1,
      "desc": """firewalld provides a dynamically managed firewall with support
for network/firewall zones to define the trust level of network. The former
firewall model with system-config-firewall/lokkit was static and every
change required a complete firewall restart. The firewall daemon on the other
hand manages the firewall dynamically and applies changes without
restarting the whole firewall. See [[FirewallD|FirewallD]]
and [[SystemConfig/firewall|system-config-firewall]]
for more information.
""" },

    {"name": "updates", "short": "Signed updates",
      "depth": 1,
      "desc": """Each stable RPM package that is published by Fedora Project is
signed with a GPG signature. By default, [[dnf|DNF]], [[yum|YUM]] and the graphical update
tools will verify these signatures and refuse to install any packages that
are not signed or have bad signatures. You should always verify the
signature of a package before you install it. These signatures ensure that
the packages you install are what was produced by the Fedora Project and
have not been altered (accidentally or maliciously) by any mirror or
website that is providing the packages. See [https://fedoraproject.org/keys this page]
for more information. [MOVE] We use a number of GPG keys to sign our software
packages. The necessary public keys are included in the relevant products and
are used to automatically verify software updates. See
[https://access.redhat.com/site/security/team/key/#package this page]
for more information.
""" },

    {"name": "selinux", "short":"SELinux",
      "depth": 1,
      "desc": """[[SELinux]] is an inode-based MAC. See [[SELinux|this page]]
and [http://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Security-Enhanced_Linux/index.html this page]
for more information.
""" },

    {"name": "selinux-targeted", "short": "SELinux targeted policy",
      "depth": 1,
      "desc": """SELinux enabled with targeted policy by default.
See [[SELinux/Policies|discussion of policies page]]
and [http://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Security-Enhanced_Linux/index.html this page]
for more information.
""" },

    {"name": "selinux_EMP", "short":"SELinux Executable Memory Protection",
      "depth": 1,
      "comment" : "execmem",
      "desc": """SELinux restricts certain memory protection operation if the appropriate boolean values enable these checks.
See [http://www.akkadia.org/drepper/selinux-mem.html this page] for more information.
""" },


    {"name": "hashing", "short": "Password hashing",
      "depth": 1,
      "desc": """The system password used for logging into Fedora is stored in
/etc/shadow. Very old style password hashes were based on DES and visible
in /etc/passwd. Modern Linux has long since moved to /etc/shadow, and for
some time now has used salted MD5-based hashes for password verification
(crypt id 1). Since MD5 is considered "broken" for some uses and as
computational power available to perform brute-forcing of MD5 increases,
modern Fedora versions have proactively moved to using salted SHA-512 based
password hashes (crypt id 6), which are orders of magnitude more difficult
to brute-force. See the crypt(3) manpage for additional details.
""" },

    {"name": "subsystems", "short":"Subsystems",
      "depth": 0,
      "section": 1,
      "desc": ""
    },

    {"name": "fscaps", "short":"Filesystem Capabilities",
      "depth": 1,
      "desc": """The need for setuid applications can be reduced via the
application of [http://www.olafdietsche.de/linux/capability/ filesystem capabilities]
using the xattrs available to most modern filesystems. This reduces the
possible misuse of vulnerable setuid applications. The kernel provides the
support and the user-space tools are available in the libcap package.
""" },

    {"name": "seccomp", "short":"PR_SET_SECCOMP",
      "depth": 1,
      "desc": """Setting SECCOMP(SECure COMPuting) for a process is meant to confine it to a small subsystem of system calls, used for specialized processing-only programs.
See [http://lwn.net/Articles/507067/ this article] and [http://lwn.net/Articles/332974/ SECCOMP article]
for more information.
""" },


    {"name": "mac", "short":"Mandatory Access Control (MAC)",
      "depth": 0,
      "section": 1, "desc": """Mandatory Access Controls specifies which subject can access specific data.
Mandatory Access Controls are handled via the kernel LSM(Linux Security Modules) hooks. MAC is based on the
security labels. Data on the system has clearance and classification data stored with security labels, which
can be accessed by specific subjects or objects.When some subject tries to access the data on the system then
the rules defined by the policy are checked to take access control decision.Security Levels are classified like
Unclassified -> Confidential -> Secret -> Top Secret.If user has clearance to access the requested object
then user will be allowed otherwise user will be denied access. It is a system wide policy which states that
who is allowed to access, an individual user cannot alter the access. MAC model is mostly used in environment
where confidentiality is important like in Government organizations like military, an example of widely used
of MAC is SELinux.Security-Enhanced Linux (SELinux) employs MAC rules to facilitate fine-grained security.

see [http://docs.fedoraproject.org/en-US/Fedora/13/html/SELinux_FAQ/index.html#id4228000 MAC]
""" },

    {"name": "SELinuxConfineUsers", "short": "SELinux user confinement",
      "depth": 1,
      "comment" : "huzaifas,mjc",
      "desc": """
Support for SELinux to confine users access on a system. Each Linux user is mapped to an SELinux user via SELinux
policy, allowing Linux users to inherit the restrictions placed on SELinux users, for example (depending on the user),
not being able to: run the X Window System; use networking; run setuid applications (unless SELinux policy permits it);
or run the su and sudo commands

<pre>
# semanage login -l

Login Name           SELinux User         MLS/MCS Range        Service

__default__          unconfined_u         s0-s0:c0.c1023       *
root                 unconfined_u         s0-s0:c0.c1023       *
system_u             system_u             s0-s0:c0.c1023       *
</pre>
All the linux users are mapped to __default__ which maps to unconfined_u user. SELinux users that are available are
guest_u, xguest_u, user_u, staff_u.

<pre>
# ls /etc/selinux/targeted/contexts/users
guest_u  root  staff_u  sysadm_u  unconfined_u  user_u  xguest_u

# ls /etc/selinux/mls/contexts/users
guest_u  root  staff_u  unconfined_u  user_u  xguest_u

* sysadm_u is not present in MLS Policy

</pre>

As listed http://docs.fedoraproject.org/en-US/Fedora/13/html/Security-Enhanced_Linux/sect-Security-Enhanced_Linux-Targeted_Policy-Confined_and_Unconfined_Users.html

{| class="wikitable"
|User     ||  Domain     ||   X Window System  ||  su and sudo  || Execute in home directory and /tmp/   ||  Networking
|-
|guest_u  ||  guest_t no ||   no               ||    no         || optional                              ||  no
|-
|xguest_u ||  xguest_t   ||   yes              ||    no         || optional                              ||  only Firefox
|-
|user_u   ||  user_t     ||   yes              ||    no         || optional                              ||  yes
|-
|staff_u  ||  staff_t    ||   yes              ||  only sudo    || optional                              ||  yes
|}

Users are defined in /etc/selinux/<target or mls>/contexts/users.

See [http://docs.fedoraproject.org/en-US/Fedora/13/html/Security-Enhanced_Linux/sect-Security-Enhanced_Linux-Targeted_Policy-Confined_and_Unconfined_Users.html Confined and Unconfined Users article]
for more information.
""" },

    {"name": "XACE", "short":"SELinux XACE",
      "depth": 1,
      "desc": """
SELinux X Access Control Extension (XACE) aims at extending SELinux to X.org system, to provide flexible fine-grained MAC to the desktop.
""" },

    {"name": "SELinuxSandbox", "short": "SELinux sandbox",
      "depth": 1,
      "desc": """
Support for SELinux to test untrusted content via a sandbox.
See [https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html-single/6.0_Release_Notes/index.html#id3184917 this page]
and [http://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html-single/6.0_Release_Notes/index.html#id3184917 this page]
for more information.
""" },


    {"name": "SELinuxDenyPtrace", "short":"SELinux Deny Ptrace",
      "depth": 1,
      "desc": """
A boolean variable to allow SELinux to turn off all processes ability to ptrace other process.
See [[Features/SELinuxDenyPtrace|this page]]
and [http://lwn.net/Articles/491440/ this] for more information.
""" },

    {"name": "SELinuxModuleLoading", "short":"SELinux restricted module loading",
      "depth": 1,
     "desc": """Support for SELinux to restrict the loading of kernel modules by unprivileged processes in confined domains
was implemented in [http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=25354c4fee169710fd9da15f3bb2abaa24dcf933 this commit].
""" },


    {"name": "namespaces", "short": "User namespaces",
      "depth": 1,
      "desc": """
User namespaces allow per-namespace mappings of user and group IDs. This means
that a process' user and group IDs inside a user namespace can be different
from its IDs outside of the namespace. Most notably, a process can have a
nonzero user ID outside a namespace while at the same time having a user ID of
zero inside the namespace; in other words, the process is unprivileged for
operations outside the user namespace but has root privileges inside the
namespace. See [http://lwn.net/Articles/532593/ this page] and [https://wiki.ubuntu.com/UserNamespace this page]
for more information. See [https://bugzilla.redhat.com/show_bug.cgi?id=917708 this bug] to track this feature.
""" },

    {"name": "systemd_namespace", "short": "/tmp namespace for systemd",
      "depth": 1,
      "desc": """
Run some services started by systemd with a private /tmp directory. This would
mitigate the chance of a service making a mistake with how it handles its /tmp
data allowing a user on the system to get a privilege escalation, since users
would not have access to the services /tmp directory.

See [http://danwalsh.livejournal.com/51459.html this page] for more information.

""" },

    {"name": "polyinstantiate", "short": "Polyinstantiate /tmp, /var/tmp and user home folders",
      "depth": 1,
      "desc": """To protect the world writable shared folders like /tmp and /var/tmp PAM (Pluggable Authentication Modules)
can help by creating namespace for users on the system. Security of a system works at different layers, Polyinstantiating these
world writable folders add an extra layer to protect from further intrusion into the system. Polyinstanting means that a new
instance of /tmp or /var/tmp directory is created for each user. This feature is implemented using ''pam_namespace.so''.
To enable this feature :

uncomment the respective lines in /etc/security/namespace.conf
<pre>#/tmp     /tmp-inst/            level      root,adm
#/var/tmp /var/tmp/tmp-inst/    level      root,adm
# Remove the line below if required to polyinstantiate HOME directory of the user
#$HOME    $HOME/$USER.inst/     level</pre>

add
<pre> session    required     pam_namespace.so </pre>
to /etc/pam.d/login. File /etc/security/namespace.conf specifies which directories will be polyinstantiated. It also specifies
how they will be polyinstantiated , what will the names of the directories which will be polyinstantiated and also for users where
Polyinstantiation would not be performed.

create the directories and set selinux context and bool value to polyinstantiate
<pre># mkdir /tmp-inst /var/tmp-inst
# chmod 000 /tmp-inst
# chmod 000 /var/tmp-inst
# chcon -R -t tmp_t /tmp-inst
# chcon -R -t tmp_t /var/tmp-inst
# setsebool polyinstantiation_enabled 1</pre>

* $ man 8 pam_namespace
* $ man 5 namespace.conf

As per reference https://www.ibm.com/developerworks/library/l-polyinstantiation/

Polyinstantiation of world-writeable directories prevents the following types of attacks:
* Race-condition attacks with symbolic links
* Exposing a file name considered secret information or useful to an attacker
* Attacks by one user on another user
* Attacks by a user on a daemon
* Attacks by a non-root daemon on a user

However, polyinstantiation does NOT prevent these types of attacks:
* Attacks by a root daemon on a user
* Attacks by root (account or escalated privilege) on any user

see [http://www.coker.com.au/selinux/talks/sage-2006/PolyInstantiatedDirectories.html Polyinstantiation of directories in an SE Linux system]
[https://www.ibm.com/developerworks/library/l-polyinstantiation/ Improve security with polyinstantiation]
""" },

    {"name": "encryption", "short":"Filesystem encryption",
      "depth": 0,
      "section": 1,
      "desc": "",
    },

    {"name": "encrypted-lvm", "short":"Encrypted LVM",
      "depth": 1,
      "desc": """Modern Fedora versions include the ability to install Fedora
onto an encrypted LVM, which allows all partitions in the logical volume,
including swap, to be encrypted. LVM uses LUKS encryption (Linux Unified Key Setup).
Except the boot partition All Other partitions can be encrypted. As the Linux Kernel
modules reside on root partition so they are also protected if Encryption is applied.
With the use of LVM Encryption user can just encrypt Physical Volume where other partitions
reside making encryption and decryption much faster. LVM is created under big encrypted
blockdevice which hides the LVM until blockdevice is unecrypted. Once the blockdevice is
unencrypted it reads the volume structure and mounts all the detected partitions at boot
time.
https://code.google.com/p/cryptsetup/
""" },

    {"name": "ecryptfs", "short":"eCryptfs",
      "depth": 1,
      "desc": """eCryptfs (Enterprise cryptographic Filesystem) is a cryptographic stacked Linux filesystem.
eCryptfs stores cryptographic metadata in the header of each file written, so that encrypted files can be
copied between hosts; the file will be decrypted with the proper key in the Linux kernel keyring. It has
been there since Kernel 2.6.19. It works at filesystem-level, so this type of encryption can be applied to
specific folders/directories as needed after creation of Filesystem.

See [http://ecryptfs.org/ eCryptfs homepage] and [http://www.linuxjournal.com/article/9400 eCryptfs Article]
for more details.
""" },

    {"name": "userspace-hardening", "short":"Userspace Hardening",
      "depth": 0,
      "section": 1,
      "desc": """Many security features are available through the default
[[CompilerFlags|compiler flags]] used to build packages and through the
kernel in Fedora.
""" },

    {"name": "nx", "short":"Non-Executable Memory (NX)",
      "depth": 1,
      "desc": """Modern processors support a feature called NX which allows a
system to control the execution of various portions of memory. Data memory
is flagged as non-executable and program memory is flagged as
non-writeable. This helps prevent certain types of buffer overflow
exploits from working as expected. Most modern CPUs protect against
executing non-executable memory regions (heap, stack, etc). Since not all
processors support the NX feature, attempts have been made to support this
feature via segment limits. A segment limit will prevent
certain portions of memory from being executed. This provides very similar
functionality to NX technology. After booting, you can see what NX protection
is in effect:

* Hardware-based (via PAE mode):
**  [    0.000000] NX (Execute Disable) protection: active

* Partial Emulation (via segment limits):
**  [    0.000000] Using x86 segment limits to approximate NX protection

For more information, see [[Security_Features?rd=Security/Features#Exec-Shield|Security Features]] page.

""" },

    {"name": "pie", "short":"Built as PIE",
      "depth": 1,
      "desc": """All programs built as Position Independent Executables (PIE)
with "-fPIE -pie" can take advantage of the exec ASLR. This protects
against "return-to-text" and generally frustrates memory corruption
attacks. This requires centralized changes to the compiler options when
building the entire archive. PIE has a large (5-10%) performance penalty
on architectures with small numbers of general registers (e.g. x86), so it
should only be used for a [[Hardened_Packages|select number of security-critical packages]].
PIE on x86_64 does not have the same penalties, and will eventually be made the
default, but more testing is required. See
[http://www.akkadia.org/drepper/nonselsec.pdf this paper] and this
[https://fedorahosted.org/fesco/ticket/1113 FESCo ticket] for more
information.

In Fedora 23 and later, all packages are built with PIE and Full RELRO. See
[[Changes/Harden_All_Packages|this page]] for details.
""" },

    {"name": "pointer-obfuscation", "short":"Pointer Obfuscation",
      "depth": 1,
      "comment": "glibc pointer encryption by default",
      "desc": """Some [http://udrepper.livejournal.com/13393.html pointers stored in glibc are obfuscated]
via PTR_MANGLE/PTR_UNMANGLE macros internally in glibc, preventing libc function pointers from being
overwritten during runtime.
""" },


    {"name": "heap-protector", "short":"Heap Protector",
      "depth": 1,
      "desc": """The GNU C Library heap protector (both automatic via
[http://www.malloc.de/en/ ptmalloc] and
[http://www.gnu.org/s/libc/manual/html_node/Heap-Consistency-Checking.html manual])
provides corrupted-list/unlink/double-free/overflow protections to the
glibc heap memory manager (first introduced in glibc 2.3.4). This stops
the ability to perform arbitrary code execution via heap memory overflows
that try to corrupt the control structures of the malloc heap memory
areas. This protection has evolved over time, adding more and more protections as
additional [http://www.phrack.com/issues.html?issue=66&id=10#article corner-cases were researched].
As it currently stands, glibc 2.10 and later appears to successfully resist
even these hard-to-hit conditions. See [http://www.redhat.com/magazine/009jul05/features/execshield/#overflows this page]
for more details.
""" },

    {"name": "fortify-source", "short":"Built with Fortify Source",
      "depth": 1,
      "desc": """Programs built with "-D_FORTIFY_SOURCE=2" (and -O1 or higher), enable several compile-time and run-time protections in glibc:
* expand unbounded calls to "sprintf", "strcpy" into their "n" length-limited cousins when the size of a destination buffer is known (protects against memory overflows).
* stop format string "%n" attacks when the format string is in a writable memory segment.
* require checking various important function return codes and arguments (e.g. system, write, open).
* require explicit file mask when creating new files.

-D_FORTIFY_SOURCE=2 also protects C++ code. See [https://www.redhat.com/archives/fedora-devel-announce/2007-September/msg00015.html this page]
for more information.
""" },

    {"name": "stack-protector", "short":"Stack Protector",
      "depth": 1,
      "comment" : "All packages compiled with stack smashing protection",
      "desc": """gcc's -fstack-protector provides a randomized stack canary
that protects against stack overflows, and reduces the chances of
arbitrary code execution via controlling return address destinations.
Enabled at compile-time. The routines used for stack checking are actually
part of glibc, but gcc is patched to enable linking against those routines
by default. See [[Security_Features?rd=Security/Features#Stack_Smash_Protection.2C_Buffer_Overflow_Detection.2C_and_Variable_Reordering|this page]]
for more information.
""" },


    {"name": "aslr", "short":"Address Space Layout Randomization (ASLR)",
      "depth": 1,
      "section": 1, "desc": """ASLR is implemented by the kernel and the ELF
loader by randomizing the location of memory allocations (stack, heap,
shared libraries, etc). This makes memory addresses harder to predict when
an attacker is attempting a memory-corruption exploit. ASLR is controlled
system-wide by the value of ''/proc/sys/kernel/randomize_va_space''.
* 0 - Turn ASLR off.
* 1 - Make the addresses of mmap(2) allocations, the stack, loaded shared libraries and the VDSO page randomized.
* 2 - Also support heap randomization in additon.

Even when randomize_va_space is set to 2, the text segment of binaries is
loaded at a static address. To make ASLR effective all segments must be
randomized. Leaving the text segment loading address non-randomized reduces the
protection provided by the ASLR since the attackers can use ret2text attacks.
The loading address of the text segement in a binary can be randomized by
building the binary as PIE (Position Independent Executable).

See [http://www.redhat.com/magazine/009jul05/features/execshield/#preventing-abuse this article] and
[http://lwn.net/Articles/190139/ this article] for more information.
""" },

    {"name": "stack-aslr", "short":"Stack ASLR",
      "depth": 2,
      "desc": """Each execution of a program results in a different stack
memory space layout. This makes it harder to locate in memory where to
attack or deliver an executable attack payload. This feature has been available
in the mainline kernel since 2.6.15.
""" },

    {"name": "mmap-aslr", "short":"Libs/mmap ASLR",
      "depth": 2,
      "desc": """Each execution of a program results in a different mmap memory
space layout. This causes the dynamically loaded libraries to get loaded into
different locations each time. This makes it harder to locate in memory
where to jump to for "return to libc" to similar attacks.  This was
available in the mainline kernel since 2.6.15.
""" },

    {"name": "exec-aslr", "short":"Exec ASLR",
      "depth": 2,
      "desc": """Each execution of a program that has been built with "-fPIE
-pie" will get loaded into a different memory location. This makes it
harder to locate in memory where to attack or jump to when performing
memory-corruption-based attacks. This was available in the mainline kernel
since 2.6.25.
""" },

    {"name": "brk-aslr", "short":"brk ASLR",
      "depth": 2,
      "desc":
"""Similar to exec ASLR, brk ASLR adjusts the memory locations relative between
the exec memory area and the brk memory area (for small mallocs). The
randomization of brk offset from exec memory was added in 2.6.22.
""" },

    {"name": "vdso-aslr", "short":"VDSO ASLR",
      "depth": 2,
      "desc": """Each execution of a program results in a random vdso location.
This has existed in the mainline kernel since 2.6.18 (x86, PPC) and
2.6.22 (x86_64). People needing ancient pre-libc6 static high vdso mappings can
use "vdso=2" on the kernel boot command line to gain COMPAT_VDSO again. See
[http://lwn.net/Articles/184734/ this article] for more information.
""" },


    {"name": "relro", "short":"Built with RELRO",
      "depth": 1,
      "comment" : "Support for ELF Data Hardening",
      "desc": """RELRO stands for RELocation Read-Only, it is a mitigation technique to harden
data sections of an ELF/process. It is used to move commonly exploited structures
in ELF binary to a read-only location. It Hardens ELF programs against loader memory
area overwrites by having the loader mark any areas of the relocation table as read-only
for any symbols resolved at load-time ("read-only relocations"). This reduces the area of
possible GOT-overwrite-style memory corruption attacks, specially the GOT is made read-only
after relocation by the dynamic linker.

RELRO can be classified into:

Partial RELRO

* Compilation: gcc -Wl,-z,relro
* ELF sections are reordered, so that ELF internal data sections (.got, .dtors, etc) precede the program's data sections (.data and .bss)
* non-PLT GOT is read-only
* GOT is writable

Full RELRO

* compilation: gcc -Wl,-z,relro,-z,now
* Supports all the features of partial RELRO
* In addition , GOT is also remapped  as read-only

In case of a bss or data overflow bug both partial and full RELRO can protect
the ELF internal data sections from being overwritten. With full RELRO a
working mitigation technique to successfully prevent the modification of GOT
entries is available. Full RELRO has been enabled for all packages in Fedora 23
and later.

In short, RELRO hardens ELF programs against loader memory area overwrites by
having the loader mark any areas of the relocation table as read-only for
any symbols resolved at load-time ("read-only relocations"). This reduces
the area of possible GOT-overwrite-style memory corruption attacks.

This information has been borrowed from [http://tk-blog.blogspot.in/2009/02/relro-not-so-well-known-memory.html this article].
"""
    },

    {"name": "bindnow", "short":"Built with BIND_NOW",
      "depth": 1,
      "desc":
"""Marks ELF programs to resolve all dynamic symbols at start-up (instead of
on-demand, also known as "immediate binding") so that the GOT can be made
entirely read-only (when combined with RELRO above).
""" },

    {"name": "proc-maps", "short":"/proc/$pid/maps protection",
      "depth": 1,
      "desc": """With ASLR, a process's memory space layout suddenly becomes
valuable to attackers. The "maps" file is
[http://lkml.org/lkml/2007/3/10/250 made read-only] except to the
process itself or the owner of the process. Went into mainline kernel with
sysctl toggle in 2.6.22. The toggle was made non-optional in 2.6.27,
forcing the privacy to be enabled regardless of sysctl settings (this is a
good thing).  """
    },

    {"name": "symlink", "short":"Symlink restrictions",
      "depth": 1,
      "desc": """A long-standing class of security issues is the symlink-based
[http://en.wikipedia.org/wiki/Time-of-check-to-time-of-use ToCToU]
race, most commonly seen in world-writable directories like ''/tmp/''. The
common method of exploitation of
[http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=tmp+symlink this flaw]
is crossing privilege boundaries when following a given symlink (i.e. a ''root''
user follows a symlink belonging to another user).

In modern Fedora version, symlinks in world-writable sticky directories (e.g.
''/tmp'') cannot be followed if the follower and directory owner do not match the
symlink owner. The behavior is controllable through the
''/proc/sys/kernel/yama/protected_sticky_symlinks'' sysctl.
""" },

    {"name": "hardlink", "short":"Hardlink restrictions",
      "depth": 1,
      "desc":
"""Hardlinks can be abused in a
[http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=hardlink similar fashion] to
symlinks above, but they are not limited to world-writable directories. If
''/etc/'' and ''/home/'' are on the same partition, a regular user can create a
hardlink to ''/etc/shadow'' in their home directory. While it retains the
original owner and permissions, it is possible for privileged programs that are
otherwise symlink-safe to mistakenly access the file through its hardlink.
Additionally, a very minor untraceable quota-bypassing local denial of service
is possible by an attacker exhausting disk space by filling a world-writable
directory with hardlinks.

In modern Fedora versions, hardlinks cannot be created to files that the user
would be unable to read and write originally, or are otherwise sensitive.
""" },

    {"name": "ptrace", "short":"ptrace scope",
      "depth": 1,
      "desc":
"""A troubling weakness of the Linux process
interfaces is that a single user is able to examine the memory and
running state of any of their processes. For example, if one application
was compromised, it would be possible for an attacker to
attach to other running processes (e.g. SSH sessions, GPG agent,
etc) to extract additional credentials and continue to immediately expand the scope
of their attack without resorting to user-assisted phishing or trojans.
It is provided by YAMA , can be enabled by CONFIG_SECURITY_YAMA in the kernel.

Independent of this configuration, processes that know they store secrets in
memory may already use <code>prctl(PR_SET_DUMPABLE,0);</code> to prevent ptrace ''and other''
memory-snooping attacks.
""" },

    {"name": "newoperator", "short": "Overflow checking in new operator",
      "depth": 1,
      "desc": """
GCC performs overflow checking in operator new[]. new operator is used to dynamically
allocate memory.It throws bad_alloc exception, header to include for using it is <new>
new() or new[]() without declaration of exception cannot signal memory exhaustion.If
there is an option to choose between calloc/malloc/new for allocation of the memory,
new should be used. If new[] is used to allocate memory then delete[] should be used to
free the allocated memory. Using delete without [] will cause memory leak. Use try-catch
block with new, as it throws exception and does not return value, though it can be forced
to return a value by using nothrow.

<pre>
 using namespace std;
 /* this should return a value */
 alpha* pt = new (nothrow) alpha[200];

 or it will throw bad_alloc exception which can be handled by the following code
 class bad_alloc : public exception {
 /* error to be thrown to be implemented here */
 };
 struct alpha_t{};

 extern const alpha_t alpha;  // indicator for allocation to prevent exceptions

 /* should throw exception */
 int* ptr = new int[100000];

 /* to avoid exception correct usage would be */
 int* ptr = new(alpha) int[100000];
</pre>

See [https://securityblog.redhat.com/2012/10/31/array-allocation-in-cxx/ Array allocation in C++ article] for
more information.

"""},

    {"name": "format-security", "short": "Built with Format Security",
      "depth": 1,
      "desc": """
Enable "-Werror=format-security" compilation flag for all packages in Fedora. Once this flag is enabled,
GCC will refuse to compile code that could be vulnerable to a string format security flaw.
see [[Changes/FormatSecurity|Format Security]] for more information
""" },

    {"name": "crypto-policy", "short": "Crypto Policy",
      "depth": 1,
      "desc": """
Unify the crypto policies used by different applications and libraries. That is allow setting a consistent
security level for crypto on all applications in a Fedora system. The implementation approach will be to
initially modify SSL libraries to respect the policy and gradually adding more libraries and applications.
See [[Changes/CryptoPolicy|Crypto Policy]] for more information.
""" },

    {"name": "stack-protector-strong", "short": "Built with Stack Protector Strong",
      "depth": 1,
      "desc": """
See [http://lwn.net/Articles/584225/ "Strong" stack protection for GCC] article for more information.
""" },

    {"name": "tamperproof", "short": "Tamper Resistant Logs",
      "depth": 1,
      "desc": """
When a system is compromised, attackers might tamper the system logs. This can
be prevented by using FSS (Forward Secure Sealing) which is implemented in
the systemd journal. Binary logs maintained by systemd are sealed at certain time
intervals. Sealing is an cryptographic operation on the logs so that any
tempering on the logs can be detected, though an attacker can completely remove
entire logs but this is likely to get noticed by the system administrator.

See [http://danwalsh.livejournal.com/58647.html Forward Secure Sealing (FSS) article] for
more information.
""" },

    {"name": "kernel-hardening", "short":"Kernel Hardening",
      "depth": 0,
      "section": 1,
      "desc": """The kernel itself has protections enabled to make it more
difficult to become compromised."""
    },

    {"name": "null-mmap", "short":"0-address protection",
      "depth": 1,
      "comment": "Support for NULL pointer dereference protection",
      "desc": """Since the kernel and userspace share virtual memory addresses,
the "NULL" memory space needs to be protected so that userspace mmap'd
memory cannot start at address 0, stopping "NULL dereference" kernel
attacks. This is possible with 2.6.22 kernels, and was implemented with
the "mmap_min_addr" sysctl setting. See [http://www.awe.com/mark/blog/20100216.html this article]
for more information.
""" },

    {"name": "block-modules", "short":"Block module loading",
      "depth": 1,
      "desc": """It is possible to
[http://www.debian.org/doc/manuals/securing-debian-howto/ch10.en.html#s-proactive remove CAP_SYS_MODULES from the system-wide capability bounding set]
, which would stop any new kernel modules from being loaded. This was another
layer of protection to stop kernel rootkits from being installed.
This feature to block module loading can be enabled setting ''1'' in
''/proc/sys/kernel/modules_disabled''.
""" },

    {"name": "dev-mem", "short": "/dev/mem protection",
      "depth": 1,
      "comment" : "Restricted access to kernel memory by default",
      "desc": """Some applications (Xorg) need direct access to the physical
memory from user-space. The special file ''/dev/mem'' exists to provide this
access. In the past, it was possible to view and change kernel memory from
this file if an attacker had root access. See [http://lwn.net/Articles/267427/ this page]
and [http://lwn.net/Articles/144107/ this page] for details.
""" },


     {"name": "dev-kmem", "short":"/dev/kmem disabled",
      "depth": 1,
      "desc": """There is no modern user of ''/dev/kmem'' any more beyond
attackers using it to load kernel rootkits.
[http://lkml.org/lkml/2008/2/10/328 CONFIG_DEVKMEM] is set to ''n''.
""" },

    {"name": "module-ronx", "short":"Module RO/NX",
      "depth": 1,
      "desc": """This feature extends CONFIG_DEBUG_RODATA to include similar
restrictions for loaded modules in the kernel. This can help resist future
kernel exploits that depend on various memory regions in loaded modules.
Enabled via the CONFIG_DEBUG_SET_MODULE_RONX option.
""" },

    {"name": "kptr-restrict", "short":"Kernel Address Display Restriction",
      "depth": 1,
      "desc": """When attackers try to develop ''run anywhere'' exploits for
kernel vulnerabilities, they frequently need to know the location of
internal kernel structures. By treating kernel addresses as sensitive
information, those locations are not visible to regular local users.
''/proc/sys/kernel/kptr_restrict'' is set to ''1'' to block the reporting of
known kernel address leaks. Additionally, various files and directories were
made readable only by the root user: ''/boot/vmlinuz'', ''/boot/System.map'',
''/sys/kernel/debug/'', ''/proc/slabinfo''.
""" },

    {"name": "blacklist-rare-net", "short":"Blacklist Rare Protocols",
      "depth": 1,
      "desc": """Normally the kernel allows all network protocols to be
autoloaded on demand. Many of these protocols are old, rare, or
generally of little use to the average Fedora user and may contain
undiscovered exploitable vulnerabilities. These include: ax25, netrom, x25,
rose, decnet, econet, rds, and af_802154. If any of the protocols are needed,
they can speficially loaded via modprobe, or the
''/etc/modprobe.d/blacklist-rare-network.conf'' file can be updated to remove
the blacklist entry. A FESCo proposal to do this for Fedora is in progress.
""" },

    {"name": "kernel-protect-rodata", "short":"Write-protect kernel .rodata sections",
      "depth": 1,
      "comment" : "mjc, Read-only data sections",
      "desc": """Enabled write-protection for kernel read-only data structures by default.
See [http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=63aaf3086baea7b94c218053af8237f9dbac5d05 this commit]
for details. This makes sure that certain kernel data sections are marked
to block modification. This helps protect against some classes of kernel
rootkits. Enabled via the CONFIG_DEBUG_RODATA option.
""" },

    {"name": "kernel-stack-protector", "short":"Kernel Stack Protector",
      "depth": 1,
      "comment" : "mjc,  Enabled kernel -fstack-protector buffer overflow detection by default<F12>",
      "desc": """
Similar to the stack protector used for ELF programs in userspace, the kernel
can protect its internal stacks as well. This feature is enabled via the
CONFIG_CC_STACKPROTECTOR option.

See commits [http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=0a4254058037eb172758961d0a5b94f4320a1425 1],
[http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=b62a5c740df1e3d49a97349fce0c6a23f633d7fe 2]
and [http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=3162f751d04086a9d006342de63ac8f44fe0f72a 3]
for more details.
""" },

    {"name": "sVirt", "short":"sVirt labelling",
      "depth": 1,
      "comment" : "mjc",
      "desc": """
Support for sVirt labelling to provide security over guest instances.
See [https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html-single/Security-Enhanced_Linux/index.html#id4232619 this page]
for more information.
""" },

    {"name": "syn-cookies", "short":"SYN cookies",
      "depth": 1,
      "desc": """When a system is overwhelmed by new network connections, SYN
cookie use is activated, which helps mitigate a SYN-flood attack.
This feature can be controlled by ''/proc/sys/net/ipv4/tcp_syncookies'' file.
""" },


    {"name": "seccomp-filter", "short":"Syscall Filtering",
      "depth": 1,
      "desc": """Programs can filter out the availability of kernel syscalls by
using the [https://lkml.org/lkml/2011/6/23/784 seccomp_filter interface].
This is done in containers or sandboxes that want to further limit the exposure
to kernel interfaces when potentially running untrusted software.
""" },

    {"name": "secureboot", "short": "Secure Boot Support",
      "depth": 1,
      "desc": """
"Secure Boot" describes a UEFI feature by which malware is prevented from
inserting itself into the boot process before the operating system loads.

For more in-depth information about Secure Boot see [[Features/SecureBoot|SecureBoot]],
[http://docs.fedoraproject.org/en-US/Fedora/18/html/UEFI_Secure_Boot_Guide/chap-UEFI_Secure_Boot_Guide-What_is_Secure_Boot.html this] and
[http://www.uefi.org/sites/default/files/resources/UEFI_Secure_Boot_in_Modern_Computer_Security_Solutions_2013.pdf this]
articles.
""" },

    {"name": "notes", "short": "Additional Documentation",
     "depth": -1, "skip": True,
     "desc": """
* Coordination with Ubuntu: https://wiki.ubuntu.com/Security/Features
* Coordination with Debian: http://wiki.debian.org/Hardening
* Gentoo's Hardening project: http://www.gentoo.org/proj/en/hardened/hardened-toolchain.xml
""" },




]
