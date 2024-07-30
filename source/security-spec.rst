.. _security-spec:

Intel® Trust Domain Extension Linux Guest Kernel Security Specification
#########################################################################

Contributors:

Andi Kleen, Elena Reshetova, Wenhui Zhang

Purpose and Scope
=================

This document describes the security architecture of
the Linux guest kernel running inside the TDX guest.

The main security goal of Intel® Trust Domain Extension (Intel® TDX)
technology is to remove the need for a TDX guest to trust the host and
virtual machine manager (VMM). It is important to note that this
security objective is not unique to the TDX architecture, but it is
common across all confidential cloud computing solutions (CCC) (such as
TDX, AMD SEV, etc) and therefore many aspects described below will be
applicable to other CCC technologies.


本文档描述了在 TDX 客户端内运行的 Linux 客户端内核的安全架构。

Intel® Trust Domain Extension (Intel® TDX) 技术的主要安全目标是消除 TDX 客户端对主机和虚拟机管理器 (VMM) 的信任需求。需要注意的是，这一安全目标不仅限于 TDX 架构，而是适用于所有保密云计算解决方案（CCC），如 TDX、AMD SEV 等。因此，以下描述的许多方面也适用于其他 CCC 技术。


Threat model
============

The Trusted Computing Base (TCB)
for the Linux TDX SW stack shown in Figure 1 includes the Intel
platform, the TDX module, and the SW stack running inside the TDX guest.

Linux TDX 软件堆栈的可信计算基 (TCB) 如图 1 所示，包括 Intel 平台、TDX 模块以及在 TDX 客户端内运行的软件堆栈。

.. figure:: images/linux-tdx-sw-stack.png
   :width: 3.63944in
   :height: 3.65625in

   Figure 1. Linux TDX 1.0 SW stack




The major security objectives of the TDX guest kernel security architecture are to help to prevent
privilege escalation as well as kernel data confidentiality/integrity
violations by the untrusted VMM. The denial-of-service (DoS) attacks
towards the TDX guest kernel is out of scope here since
the TDX guest resources are fully under the control of the VMM and are
able to perform DoS towards the TDX guest by default.

The TDX module and the Intel platform help ensure the protection of the TDX
guest memory and registers. However, they cannot protect the TDX guest
from host/VMM attacks that leverage existing communication interfaces
between the host/VMM and the guest:

-  TDVMCALL hypercalls (through the TDX-module)

-  Shared memory for IO

The primary goal of the security architecture described below is to help to
protect the TDX Linux guest kernel from attacks from the hypervisor
through these communication interfaces. Additionally, there should not
be any new additional attack vectors introduced towards the TDX Linux
guest kernel (ring 0) from the TDX guest userspace (ring 3). The TDX
guest userspace is omitted from the scope of this threat model. The
threat model does not address any threats made possible by the TDX guest
userspace directly using the above-mentioned interfaces exposed to an
untrusted host/VMM. For example, if the TDX guest userspace enables
debug or test tools that perform MMIO or pci config space reading on
their own but do not carefully validate the input that comes from
untrusted host/VMM, many additional attacks are possible. This threat
model also assumes the KVM/Qemu to be the hypervisor running the
protected TDX guest. As a result, other hypervisors and their hardening
are also out of the scope of this document. Another potential attack
vector that is not covered by this threat model is abusing the Linux
kernel printout and debug routines that can now take parameters directly
from the untrusted host/VMM.


TDX 客户端内核安全架构的主要安全目标是帮助防止未受信任的 VMM 提升权限以及内核数据机密性/完整性违反。拒绝服务 (DoS) 攻击对于 TDX 客户端内核来说不在本文讨论的范围内，因为 TDX 客户端的资源完全由 VMM 控制，默认情况下可以对 TDX 客户端执行 DoS 攻击。

TDX 模块和 Intel 平台帮助确保 TDX 客户端内存和寄存器的保护。然而，它们不能保护 TDX 客户端免受主机/VMM 利用现有通信接口进行的攻击：

1. 通过 TDX 模块的 TDVMCALL 超级调用
2. 用于 IO 的共享内存


下文描述的安全架构的主要目标是帮助保护 TDX Linux 客户端内核免受来自虚拟机管理程序通过这些通信接口的攻击。此外，不应引入任何新的攻击向量，使得 TDX Linux 客户端内核（ring 0）可能受到来自 TDX 客户端用户空间（ring 3）的攻击。TDX 客户端用户空间不在此威胁模型的范围内。此威胁模型不涉及任何由 TDX 客户端用户空间直接使用上述暴露给不受信任的主机/VMM 的接口而可能导致的威胁。例如，如果 TDX 客户端用户空间启用调试或测试工具，这些工具自己执行 MMIO 或 PCI 配置空间读取但没有仔细验证来自不受信任的主机/VMM 的输入，那么可能会出现许多额外的攻击。此威胁模型还假设 KVM/Qemu 是运行受保护的 TDX 客户端的虚拟机管理程序。因此，其他虚拟机管理程序及其加固也不在本文的范围内。另一个不包括在此威胁模型中的潜在攻击向量是滥用 Linux 内核打印和调试例程，这些例程现在可以直接从不受信任的主机/VMM 获取参数。


The overall threat mitigation matrix is shown in Table below.

整体的威胁缓解矩阵如表所示。

.. list-table:: TDX guest Linux kernel threat mitigation matrix
   :widths: auto
   :align: center
   :header-rows: 1

   * - Threat name
     - Threat description
     - Mitigation mechanisms
     - Links to detailed description
   * - (NRDD) Non-robust device drivers 非健壮设备驱动程序 (NRDD)
     - Malicious input (MSR, CPUID, PCI config space, PortIO, MMIO, SharedMemory/DMA, KVM Hypercalls) is consumed from the host/VMM by a non-harden device driver that results in a host/VMM -> guest kernel privilege escalation 

       恶意输入 (MSR、CPUID、PCI 配置空间、PortIO、MMIO、共享内存/DMA、KVM 超级调用) 从主机/VMM 传递给非硬化的设备驱动程序，导致主机/VMM -> 客户端内核权限升级。

     - 1. Disable most of the drivers with the driver filter. Limitation: does not prevent driver __init function from executing.  Some drivers might use legacy registration and avoid filtering. 
       2. Disable ACPI drivers by limiting a set of allowed ACPI tables (this typically also results in __init function not run beyond first ACPI table presence check)
       3. Perform hardening of enabled drivers

       1. 使用驱动程序过滤器禁用大多数驱动程序。限制：无法防止驱动程序 __init 函数执行。某些驱动程序可能使用遗留注册并避免过滤。
       2. 通过限制允许的 ACPI 表集禁用 ACPI 驱动程序（这通常还导致 __init 函数不会在首次 ACPI 表存在检查之后运行）。
       3. 加强启用的驱动程序的安全。

     - 1. See `Device filter mechanism`_
       2. See `BIOS-supplied ACPI tables and mappings`_ 
       3. See :ref:`tdx-guest-hardening`


   * - (NRDDI/L) Non-robust device driver’s __init function or legacy non-robust driver 非健壮设备驱动程序的 __init 函数或遗留非健壮驱动程序 (NRDDI/L)

     - The device filter does not prevent driver initialization function from executing. For 5.15 kernel there are 198 unique __init functions with 5198 unique code locations that can consume a malicious input (MSR,CPUID, PCI config space, PortIO, MMIO, KVM hypercalls) from host/VMM that can result in a host/VMM -> guest kernel privilege escalation.

       设备过滤器无法防止驱动程序初始化函数的执行。对于 5.15 内核，有 198 个唯一的 __init 函数和 5198 个唯一的代码位置，这些位置可以接收来自主机/VMM 的恶意输入 (MSR、CPUID、PCI 配置空间、PortIO、MMIO、KVM 超级调用)，导致主机/VMM -> 客户端内核权限升级。


     - 1. For PCI config space: pci config space access restrictions
       2. For MMIO: opt-in MMIO sharing 
       3. For Port IO: PortIO filter
       4. For KVM hypercalls: restrict to a minimal allowed set
       5. For MSRs: TDX module limits host-provided MSRs + code audit
       6. For CPUIDs: only allow SW range 0x40000000 - 0x400000FF

       1. 对于 PCI 配置空间：PCI 配置空间访问限制
       2. 对于 MMIO：选择性启用 MMIO 共享
       3. 对于 Port IO：PortIO 过滤器
       4. 对于 KVM 超级调用：限制到最小允许集
       5. 对于 MSR：TDX 模块限制主机提供的 MSR + 代码审核
       6. 对于 CPUID：只允许 SW 范围 0x40000000 - 0x400000FF

     - 1. See `PCI config space`_ 
       2. See `MMIO`_
       3. See `IO ports`_
       4. See `KVM Hypercalls`_
       5. See `MSRs`_
       6. See `CPUID`_

   * - (NRCKC) Non-robust core kernel code 非健壮核心内核代码 (NRCKC)
     - Malicious input (MSR,CPUID, PCI config space, PortIO, MMIO, SharedMemory/DMA, KVM Hypercalls) is consumed from the host/VMM by a core Linux code that results in a host/VMM -> guest kernel privilege escalation
       恶意输入 (MSR、CPUID、PCI 配置空间、PortIO、MMIO、共享内存/DMA、KVM 超级调用) 从主机/VMM 传递给核心 Linux 代码，导致主机/VMM -> 客户端内核权限升级。

     - 1. Disable complex features that are not required for TDX guest kernel and can consume input from VMM/host. Limitation: disabling of some features is not straightforward.
       2. As a defense in depth rely on mitigations from (NRDDI/L) to minimize the open attack surface (especially for MMIO, PortIO, CPUIDs and MSRs).  
       3. Perform hardening of enabled code

       1. 禁用不需要的复杂功能，这些功能可能会从 VMM/主机接收输入。限制：某些功能的禁用并不简单。
       2. 作为深度防御，依靠来自 (NRDDI/L) 的缓解措施来最小化开放攻击面（特别是对于 MMIO、PortIO、CPUID 和 MSR）。
       3. 加强启用的代码的安全。

     - 1. See tbd
       2. See links from NRDDI/L
       3. See :ref:`tdx-guest-hardening`


   * - (HCSG) Host/VMM controlled Spectre v1 gadget  主机/VMM 控制的 Spectre v1 gadget (HCSG)
     - Host/VMM uses a spectre v1 gadget conditioned on the host/VMM controlled input (MSR,CPUID, PCI config space, PortIO, MMIO, SharedMemory/DMA, KVM Hypercalls) and uses that to break confidentiality of the guest VM
       主机/VMM 使用基于主机/VMM 控制输入 (MSR、CPUID、PCI 配置空间、PortIO、MMIO、共享内存/DMA、KVM 超级调用) 的 Spectre v1 gadget 来破坏客户端 VM 的机密性。

     - 1. Minimize the attack surface by using mitigations from threats (NRDD), (NRDDI/L) and (NRCKC) 
       2. Perform a static code audit of the remaining surface to identify the potential gadgets and fix them

       1. 使用 (NRDD)、(NRDDI/L) 和 (NRCKC) 的缓解措施来最小化攻击面。
       2. 对剩余的表面进行静态代码审核，以识别潜在的 gadget 并修复它们。
   
     - 1. See links from NRDD, NRDDI/L and NRCKC
       2. See `Transient Execution attacks and their mitigation`_


   * - (NRAA) Non-robust AML interpreter or ACPI code 非健壮的 AML 解释器或 ACPI 代码 (NRAA)
     - Malicious input is consumed from the host/VMM via an ACPI table (provided by the host/VMM via TDVF virtual FW) that results in a host/VMM -> guest kernel  privilege escalation
       恶意输入通过 ACPI 表（由主机/VMM 通过 TDVF 虚拟 FW 提供）传递到客户端内核，导致主机/VMM -> 客户端内核权限升级。

     - 1. ACPI tables are measured to TDX attestation registers, and their measurements included as part of remote attestations. Limitation: Even benign looking ACPI table can
          exploit some unknown bug in AML interpreter or ACPI code. There are 55+ ACPI tables, some containing a lot of functionality/code.
       2. Disable most of non-needed ACPI tables via ACPI filter

       1. ACPI 表被测量到 TDX 证明寄存器中，其测量值包含在远程证明中。限制：即使是良性的 ACPI 表也可能利用 AML 解释器或 ACPI 代码中的一些未知漏洞。存在 55 个以上的 ACPI 表，有些包含大量功能/代码。
       2. 通过 ACPI 过滤器禁用大多数不需要的 ACPI 表。

     - 1. TDX guest virtual FW (TDVF) enforces it. See `TDX guest virtual firmware <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-virtual-firmware-design-guide-rev-1.01.pdf>`_ 
       2. See `BIOS-supplied ACPI tables and mappings`_ 

   * - (HCR) Host/VMM controlled randomness 主机/VMM 控制的随机性 (HCR)
     - Host/VMM can observe or affect the state of Linux RNG guest kernel (due to interrupts being the main default source of entropy) and break cryptographic security of all guest mechanisms consuming RNG output
       主机/VMM 可以观察或影响 Linux RNG 客户端内核的状态（由于中断是主要的默认熵源）并破坏所有消费 RNG 输出的客户端机制的加密安全性。


     - Enforce addition of entropy using RDRAND/RDSEED and avoid fallbacks to insecure jiffies

       强制使用 RDRAND/RDSEED 增加熵，避免回退到不安全的 jiffies。

     - See `Randomness inside TDX guest`_ 

   * - (HCT) Host/VMM controlled time 主机/VMM 控制的时间 (HCT)


     - Host/VMM can modify/affect the time visible inside TDX guest and break security of all guest mechanisms depending on a secure time (rollback prevention, etc.)
       主机/VMM 可以修改/影响 TDX 客户端内的时间，并破坏所有依赖安全时间的客户端机制的安全性（防止回滚等）。

     - Disable all mechanisms for the host/VMM to affect guest time. Only rely on TSC timer, which is guaranteed by TDX module
       禁用所有主机/VMM 影响客户端时间的机制。仅依赖 TSC 计时器，由 TDX 模块保证。

     - See `TSC and other timers`_ 

   * - (II) Injected interrupts 注入的中断 (II)

     - Host/VMM can inject an interrupt into the guest with malicious inputs

       主机/VMM 可以向客户端注入带有恶意输入的中断。

     - Injecting interrupts (via posted-interrupt mechanism) is not allowed for exception vectors 0-30. NMI injection is possible with the assistance of TDX module

	注入中断（通过发布中断机制）不允许用于异常向量 0-30。NMI 注入可能需要 TDX 模块的帮助。

     - See `Interrupt handling and APIC`_ 

   * - (LIPC/P) Lost IPIs/reliable panic 丢失的 IPI/可靠的 panic (LIPC/P)
     - Host/VMM can drop IPIs between vcpus on the guest and as a result attempt to cause some unexpected behavior in guest

       主机/VMM 可以在客户端的 vCPU 之间丢失 IPI，从而导致客户端出现意外行为。

     - Code audit on consequences of lost IPIs (no findings so far). Panic seems to be safe.  
      对丢失的 IPI 后果进行代码审核（目前尚无发现）。Panic 看起来是安全的。

     - N/A


TDX Linux guest kernel overall hardening methodology
====================================================

Document :ref:`tdx-guest-hardening` describes the hardening methodology
that is used to perform systematic audits and fuzzing of the communication
interfaces exposed to the malicious hypervisor. This document covers the
kernel subsystems that are relevant to the described threat model and provides
details on their hardening principles. The overall security principle is
that in case of any corruption event, the safest default option is to
raise the kernel panic.

文档 :ref:tdx-guest-hardening 描述了用于对暴露给恶意虚拟机监控程序的通信接口进行系统审核和模糊测试的加固方法。该文档涵盖了与描述的威胁模型相关的内核子系统，并提供了其加固原则的详细信息。总体的安全原则是，在任何损坏事件发生时，最安全的默认选项是触发内核崩溃（kernel panic）。

.. _sec-device-filter:

Device filter mechanism
=======================

As stated above, the primary goal of the security architecture described
in this document is to help protecting the TDX Linux guest kernel from hypervisor
attacks through TDVMCALL or shared memory communication interfaces. 
The detailed description of when these interfaces are used in TDX guest kernel
can be found below in the section `TDVMCALL-hypercall-based communication interfaces`_,
but our analysis of the kernel code has shown that the biggest users of such
interfaces are device drivers (more than 95%). Every time a driver
performs a port IO or MMIO read, access a pci config space or reads values
from MSRs or CPUIDs, there is a possibility for a malicious hypervisor to
inject a malformed value.

Fortunately, only a small subset of device drivers are required for the TDX guest
operation (for Linux TDX SW reference stack it is a subset of virtio drivers
described in `VirtIO and shared memory`_), so most of the attack surface can
be disabled by creating a small list of allowed device drivers. This is the
main goal of the guest runtime device filter. It allows to define an allow or
deny list for device drivers and prevents non-authorized device driver's
probe functions from running (note: driver's init functions are able to execute).
It also automatically sets to 'shared' the MSI mailboxes and MMIO mappings of the
authorized device drivers, if the latter ones are created using pci\_iomap\_* or devm\_ioremap*
interfaces. For MMIO mappings created using plain ioremap\_* style interface,
a driver code needs to be modified to either use the above mentioned pci\_iomap\_*/devm\_ioremap*
interfaces or a new ioremap\_driver\_hardened interface that manually sets the
mapping to 'shared' also. 

Additionally when device filter is enabled (see section `Kernel command line`_
on how it can be disabled for debug purpose from the command line), there are
other security mechanisms that are enabled for the TDX guest Linux
kernel, namely Port IO filter is active (see section `IO ports`_ for details),
ACPI table allow list is enforced (see section `BIOS-supplied ACPI tables and mappings`_ 
for details) and pci config space access from non-authorized device drivers is limited
(see section `PCI config space`_ for details).
If disabling of the device filter or associated mechanisms is
desired for debug purpose, please consult section `Kernel command line`_ on how
to change configuration of these mechanisms using command line, i.e. modify
allow/deny list of the device filter, modify the list of allowed ACPI tables, etc.


如上所述，本文件所描述的安全架构的主要目标是帮助保护 TDX Linux 客户端内核免受通过 TDVMCALL 或共享内存通信接口的虚拟机管理程序（hypervisor）攻击。关于这些接口在 TDX 客户端内核中的使用情况的详细描述，可以在下面的“基于 TDVMCALL 超调用的通信接口”部分找到，但我们对内核代码的分析表明，这些接口的最大用户是设备驱动程序（超过 95%）。每当驱动程序执行端口 IO 或 MMIO 读取、访问 PCI 配置空间或从 MSR 或 CPUID 中读取值时，恶意虚拟机管理程序都有可能注入格式错误的值。

幸运的是，TDX 客户端操作所需的设备驱动程序只是一个小子集（对于 Linux TDX SW 参考堆栈，它是 VirtIO 和共享内存 部分中描述的 VirtIO 驱动程序的子集），因此大部分攻击面可以通过创建一个允许的设备驱动程序的小列表来禁用。这是客户机运行时设备过滤器的主要目标。它允许为设备驱动程序定义允许或拒绝列表，并防止未授权的设备驱动程序的探测功能运行（注意：驱动程序的初始化功能可以执行）。如果后者是使用 pci_iomap_* 或 devm_ioremap* 接口创建的，它还会自动将授权设备驱动程序的 MSI 邮箱和 MMIO 映射设置为“共享”。对于使用普通 ioremap_* 风格接口创建的 MMIO 映射，驱动程序代码需要进行修改，要么使用上述 pci_iomap_* /devm_ioremap* 接口，要么使用新的 ioremap_driver_hardened 接口，手动将映射也设置为“共享”。

此外，当设备过滤器启用时（有关如何从命令行禁用它以进行调试目的的说明，请参见 Kernel command line 部分），TDX 客户端 Linux 内核还会启用其他安全机制，即启用端口 IO 过滤器（详情请参见 IO ports 部分）、强制执行 ACPI 表允许列表（详情请参见 BIOS-supplied ACPI tables and mappings 部分）以及限制非授权设备驱动程序的 PCI 配置空间访问（详情请参见 PCI config space 部分）。如果出于调试目的希望禁用设备过滤器或关联机制，请参考 Kernel command line 部分了解如何使用命令行更改这些机制的配置，例如修改设备过滤器的允许/拒绝列表，修改允许的 ACPI 表列表等。

.. _sec-device-passthrough:

Device passthrough
------------------

In some deployment models it might be desirable to enable a device passthrough
for a TDX guest. In the current TDX 1.0 model, it is only possible via the usage
of a shared memory, i.e. it is not possible to let the devices to access the TDX
guest private memory. As a result, when a new passthrough device is being enabled
for a TDX guest, the corresponding device driver in the TDX guest must be authorised
to run by the device filter mechanism and its MMIO pages must be mapped as shared
for the communication to happen. This can be done using the following kernel command
attribute: **authorize_allow_devs=pci:<ven_id:dev_id>**. However, based on the type of
the interface that device driver uses to create the MMIO mappings, it might not be
possible to automatically share these pages with the host: 

-  If device driver uses **devm_ioremap*()** or **pci_iomap*()**-style interfaces, the
   sharing works fine

-  If device driver uses a legacy **ioremap*()**-style interfaces, the
   sharing won't work and the corresponding device driver must be changed
   to either use the above interfaces or alternatively a dedicated
   **ioremap_driver_hardening()** interface that explicitly indicates that an
   MMIO mapping must be shared with the host

Similar to a non-passthrough case, any device driver enabled in the TDX guest
using the above mechanism must be hardened to withstand the attacks from hypervisor
through TDVMCALL or shared memory communication interfaces. Moreover, since
the device passthrough for TDX 1.0 is using shared memory, any data placed in
this memory can be manipulated by the host/hypervisor and must be protected where possible
using application-level security mechanisms, such as encryption and authentication.

在某些部署模型中，可能希望为 TDX 客户端启用设备直通。在当前的 TDX 1.0 模型中，这只能通过使用共享内存实现，即设备无法访问 TDX 客户端的私有内存。因此，当为 TDX 客户端启用新的直通设备时，必须通过设备过滤机制授权在 TDX 客户端中运行相应的设备驱动程序，并且其 MMIO 页必须映射为共享，以便进行通信。这可以使用以下内核命令属性完成：authorize_allow_devs=pci:<ven_id
>。然而，根据设备驱动程序用于创建 MMIO 映射的接口类型，可能无法自动与主机共享这些页面：

1. 如果设备驱动程序使用 devm_ioremap()* 或 pci_iomap()* 风格的接口，共享工作正常。

2. 如果设备驱动程序使用传统的 ioremap()* 风格的接口，共享将无法工作，相应的设备驱动程序必须更改为使用上述接口，或者使用专门的 ioremap_driver_hardening() 接口，明确指示 MMIO 映射必须与主机共享。


类似于非直通情况，使用上述机制在 TDX 客户端中启用的任何设备驱动程序必须进行加固，以抵御通过 TDVMCALL 或共享内存通信接口的虚拟机管理程序攻击。此外，由于 TDX 1.0 的设备直通使用共享内存，放置在此内存中的任何数据都可能被主机/虚拟机管理程序操纵，必须尽可能使用应用级安全机制（如加密和认证）进行保护。


.. _sec-tdvmcall-interfaces:

TDVMCALL-hypercall-based communication interfaces
=================================================

TDVMCALLs are used to communicate between the TDX guest and the
host/VMM. The host/VMM can try to attack the TDX guest kernel by
supplying a maliciously crafted input as a response to a TDVMCALL. While
TDVMCALLs are proxied via the TDX module, only a small portion of them
(mainly some CPUIDs and MSRs) are controlled and enforced by the TDX
module. Most of the TDVMCALLs are passed through and their values are
controlled by the host/VMM. Instead of inserting the TDVMCALL directly
in many code paths within the guest kernel, a #VE handler is used as a
primary centralized TDVMCALL invocation place. However, for some cases
TDVMCALL can be also invoked directly to boost the performance
for a certain hot code path. The #VE handler is invoked by the
TDX module for the actions it cannot handle. The #VE handler either
decodes the executed instruction (using the standard Linux x86
instruction decoder) and converts it into a TDVMCALL or rejects it
(panic). The implementation of the #VE handler is simple and does not
require an in-depth security audit or fuzzing since it is not the actual
consumer of the host/VMM supplied untrusted data. However, it does
implement a simple allow list for the port IO filtering (see `IO ports`_ ).


TDVMCALL 是用于 TDX 客户端与主机/VMM 之间通信的接口。主机/VMM 可能会尝试通过提供恶意制作的输入来攻击 TDX 客户端内核，作为对 TDVMCALL 的响应。尽管 TDVMCALL 是通过 TDX 模块代理的，但其中只有一小部分（主要是一些 CPUID 和 MSR）由 TDX 模块控制和强制执行。大多数 TDVMCALL 是直接传递的，它们的值由主机/VMM 控制。

为了集中管理 TDVMCALL 的调用，#VE 处理程序被用作主要的中心化调用点，而不是在客户端内核的多个代码路径中直接插入 TDVMCALL。然而，在某些情况下，为了提高某些热点代码路径的性能，也可能会直接调用 TDVMCALL。TDX 模块会在其无法处理的操作时调用 #VE 处理程序。#VE 处理程序要么使用标准的 Linux x86 指令解码器解码执行的指令并将其转换为 TDVMCALL，要么拒绝它（引发 panic）。由于 #VE 处理程序并不是主机/VMM 提供的不受信任数据的实际消费者，因此其实现简单，不需要进行深入的安全审计或模糊测试。不过，它确实实现了一个简单的端口 IO 过滤器的允许列表。

.. _sec-mmio:

MMIO
----

MMIO is controlled by the untrusted host and handled through #VE for
most cases, or a special fast path through pci iomap for
performance-critical cases. The instructions in the kernel are trusted.
The #VE handler will decode a subset of instructions using the Linux
instruction decoder. We only care about users that read from MMIO.

MMIO 主要通过 #VE 进行控制，或在性能关键情况下通过 PCI iomap 特殊快速路径处理。内核中的指令是受信任的。#VE 处理程序将使用 Linux 指令解码器解码一部分指令。我们只关注从 MMIO 读取数据的用户。

Kernel MMIO
~~~~~~~~~~~

By default, all MMIO regions reside in the TDX guest private memory
are not accessible to the host/VMM. To explicitly share a MMIO region,
the device must be authorized through the device filter framework,
enabling MMIO operations. The handling of the
MMIO input from the untrusted host/VMM must be hardened (see
:ref:`tdx-guest-hardening` for more information).

The static code analysis tool should generate a list of all MMIO users
based on use of the standard io.h macros. All portable code should use
these macros. The only known exception to this is the legacy MMIO APIC
direct accesses, which is disabled (see `Interrupt handling and APIC`_ ).

Open: there might be other non-portable (x86-specific) code that does
not use the io.h macros, but directly accesses IO mappings. Sparse
should be able to find those using the \_\_iomem annotations.

默认情况下，所有 MMIO 区域都位于 TDX 客户端的私有内存中，主机/VMM 无法访问。如果需要显式共享 MMIO 区域，则必须通过设备过滤器框架授权设备，启用 MMIO 操作。来自不受信任的主机/VMM 的 MMIO 输入的处理必须进行加固（有关更多信息，请参见 :ref:tdx-guest-hardening）。

静态代码分析工具应生成所有 MMIO 用户的列表，基于标准 io.h 宏的使用。所有可移植代码应使用这些宏。唯一已知的例外是禁用的遗留 MMIO APIC 直接访问（参见 中断处理和 APIC_）。

尚待解决：可能还有其他不使用 io.h 宏的不可移植（特定于 x86）的代码，而是直接访问 IO 映射。Sparse 应该能够使用 __iomem 注释找到这些代码。



User MMIO
~~~~~~~~~

In the current Linux implementation user MMIO is not supported
and results in SIGSEGV. Therefore, it cannot be used to attack
the kernel (other than DoS).


在当前的 Linux 实现中，用户 MMIO 不受支持，会导致 SIGSEGV。因此，它不能用来攻击内核（除了 DoS 以外）。

.. _sec-APIC:

Interrupt handling and APIC
---------------------------

TDX guest must use virtualized x2APIC mode.
Legacy xAPIC (using MMIO) is disabled via special checks in the
guest's kernel APIC code, as well as enforced by the TDX module.

The x2APIC MSRs are either proxied through the TDVMCALL hypercall
(and handled by the untrusted hypervisor) or handled as access
to a VAPIC page. The later ones are considered trusted, but the
first group requires hardening similar as untrusted MSR access
described in `MSRs proxied through TDVMCALL and controlled by host`_.
For the detailed description on specific x2APIC MSR behavior
please see section 10.9 in `Intel TDX module architecture specification <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>`_.

Untrusted VMM can inject both non-NMI interrupts (via posted-interrupt
mechanism) or NMI interrupts. However, TDX module does not allow VMM
injecting interrupt vectors in range 0-30 via posted-interrupt mechanism,
which drastically reduces the exposed attack surface towards the untrusted VMM. 
The rest of above interrupts are considered controlled by the host and
therefore the guest kernel code that handles them must be audited and
fuzzed as any other code that receives malicious host input.

IPIs are initiated by triggering TDVMCALL on the x2APIC ICR MSRs. The
host controls the delivery of the IPI, so IPIs might get lost. We need
to make sure all missing IPIs result in panics or stop the operation (in
case the timeout is controlled by the host). This should be already
handled by the normal timeout in smp\_call\_function\*().


TDX 客户端必须使用虚拟化 x2APIC 模式。通过特殊检查禁用遗留 xAPIC（使用 MMIO），并由 TDX 模块强制执行。

x2APIC MSR 要么通过 TDVMCALL 超级调用代理（由不受信任的超级管理程序处理），要么作为 VAPIC 页的访问处理。后一种情况被认为是可信的，但前者需要加固，类似于 MSRs proxied through TDVMCALL and controlled by host_ 中描述的不受信任的 MSR 访问。有关特定 x2APIC MSR 行为的详细说明，请参见 Intel TDX 模块架构规范 <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>_ 的第 10.9 节。

不受信任的 VMM 可以注入非 NMI 中断（通过 posted-interrupt 机制）或 NMI 中断。然而，TDX 模块不允许 VMM 通过 posted-interrupt 机制注入 0-30 范围内的中断向量，从而大大减少了暴露给不受信任的 VMM 的攻击面。上述其他中断被认为由主机控制，因此处理这些中断的客户端内核代码必须像处理任何接收恶意主机输入的代码一样进行审计和模糊测试。

IPIs 是通过在 x2APIC ICR MSR 上触发 TDVMCALL 发起的。主机控制 IPI 的传递，因此 IPI 可能会丢失。我们需要确保所有丢失的 IPI 导致 panic 或停止操作（如果超时由主机控制）。这应该已经由 smp_call_function*() 中的正常超时处理。




.. _sec-pci-config-space:

PCI config space
----------------

The host controls the PCI config space, so in general, any PCI config
space reads are untrusted. Apart from hardening the generic PCI code, there
is a special pci config space filter that prevents random initcalls from
accessing the PCI config space of unauthorized devices
not allowed by the device filter. The config space filter is implemented
by setting unauthorized devices to the “errored” state, which prevents
any config space accesses.

Inside Linux, the PCI config space is used by several entities:

主机控制 PCI 配置空间，因此一般来说，任何 PCI 配置空间的读取都是不受信任的。除了加固通用 PCI 代码外，还有一个特殊的 PCI 配置空间过滤器，防止随机 initcall 访问设备过滤器不允许的未授权设备的 PCI 配置空间。配置空间过滤器通过将未经授权的设备设置为“错误”状态来实现，阻止任何配置空间访问。

在 Linux 内部，PCI 配置空间由多个实体使用：


PCI subsystem for probing drivers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The PCI subsystem enumerates all PCI devices through PCI config space. The
host owns the config space, which is untrusted. We only support
probing through CF8 and disable MCFG config space via the ACPI table allow list.
This implies that only the first 256 bytes are supported for now. The core PCI
subsystem code has been hardened via code audit and fuzzing described in :ref:`tdx-guest-hardening`.

PCI 子系统通过 PCI 配置空间枚举所有 PCI 设备。主机拥有配置空间，该空间不受信任。我们仅支持通过 CF8 进行探测，并通过 ACPI 表允许列表禁用 MCFG 配置空间。这意味着目前仅支持前 256 字节。核心 PCI 子系统代码已通过 :ref:tdx-guest-hardening 中描述的代码审计和模糊测试进行了加固。


Allocating resources
~~~~~~~~~~~~~~~~~~~~

The kernel can allocate resources such as MMIO for pci bridges or
drivers based on the information coming from the untrusted pci config
space supplied by the host/VMM. Therefore, this allocation process needs
to be verified to withstand the potential malicious input. As a result,
the code in the core pci subsystem, as well as enabled virtio drivers
have been audited and fuzzed using the techniques described in :ref:`tdx-guest-hardening`.
Specifically, we paid attention to make sure that the allocated resource
regions do not overlap with each other or with the rest of the TD guest
memory.

内核可以根据来自不受信任的主机/VMM 提供的 PCI 配置空间的信息分配资源，例如 PCI 桥或驱动程序的 MMIO。因此，需要验证此分配过程以承受潜在的恶意输入。因此，核心 PCI 子系统中的代码以及启用的 virtio 驱动程序已使用 :ref:tdx-guest-hardening 中描述的技术进行了审计和模糊测试。我们特别注意确保分配的资源区域不会相互重叠或与 TD 客户端内存的其余部分重叠。



Drivers
~~~~~~~

All allow-listed drivers need to be audited and fuzzed for all pci config space
interactions they have with the host. Initially this is only a very small list
of virtio devices (see `VirtIO and shared memory`_).

所有允许列表中的驱动程序都需要审核和模糊测试它们与主机的所有 PCI 配置空间交互。最初，这只是非常小的一部分 virtio 设备（参见 VirtIO 和共享内存_）。

User programs accessing PCI config space
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

User programs can access PCI devices directly through sysfs or /dev/mem.
This could be an attack vector if the user program has an exploitable
hole in parsing PCI config space or MMIO. If the user programs are using the
Linux-supplied PCI enumeration (/sys/bus/pci), the PCI device allow list
will protect user programs to some degree. But it won’t protect programs
that try to directly access devices that are on the allow list (like
virtio devices).

It’s also possible, for userspace programs to access the PCI config space directly
through CF8 port IO using operm/iopl() or direct read() on /dev/port. The former
case will be filtered in the TDX guest kernel #VE handler, because the handler does not
forward port IO requests to an untrusted VMM if the request came from a userspace.
The latter case (direct read on /dev/port) however is not going to be limited by
the #VE handler and a userspace program that performs this operation should be
prepared to handle untrusted input from a VMM securely. PCI config space access
through MMIO for userspace programs is not possible inside TDX guest since PCIe MCFG
config space is disabled for TDX guest and normal PCI config space is not mapped to
MMIO address space.


用户程序可以通过 sysfs 或 /dev/mem 直接访问 PCI 设备。如果用户程序在解析 PCI 配置空间或 MMIO 时有漏洞，这可能成为攻击向量。如果用户程序使用 Linux 提供的 PCI 枚举（/sys/bus/pci），PCI 设备允许列表将在某种程度上保护用户程序。但它不会保护试图直接访问允许列表中设备（如 virtio 设备）的程序。

用户空间程序还可以通过 CF8 端口 IO 使用 operm/iopl() 或直接读取 /dev/port 直接访问 PCI 配置空间。前者的情况将在 TDX 客户端内核 #VE 处理程序中被过滤，因为处理程序不会将端口 IO 请求转发给不受信任的 VMM 如果请求来自用户空间。然而，后一种情况（直接读取 /dev/port）不会受到 #VE 处理程序的限制，执行此操作的用户空间程序应准备好安全处理来自 VMM 的不受信任输入。由于 PCIe MCFG 配置空间被禁用，TDX 客户端内部的用户空间程序无法通过 MMIO 访问 PCI 配置空间，而普通 PCI 配置空间未映射到 MMIO 地址空间。


.. _sec-msrs:

MSRs
----

Nearly all MSRs used by the kernel for x86 are listed in
arch/x86/include/asm/msr-index.h, but might have aliases and ranges.
Some additional MSRs are in arch/x86/include/asm/perf\_event.h,
arch/x86/kernel/cpu/resctrl/internal.h, and arch/x86/kernel/cpu/intel.c

几乎所有内核使用的 MSR 都列在 arch/x86/include/asm/msr-index.h 中，但可能有别名和范围。一些额外的 MSR 在 arch/x86/include/asm/perf_event.h、arch/x86/kernel/cpu/resctrl/internal.h 和 arch/x86/kernel/cpu/intel.c 中。

MSRs controlled by TDX module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are two types of MSRs that are controlled by the TDX module:

-  Passthrough MSRs (direct read/write from the CPU, for example side
   channel related MSRs, such as ARCH\_CAPABILITIES)

-  Disallowed MSRs that result in #GP upon attempt to read/write
   such an MSR (for example, all IA32\_VMX\_\* KVM MSRs).

All these MSRs are controlled by the platform, are trusted, and do not
require any hardening. See section 18.1 in `Intel TDX module architecture specification <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>`_ for the exact list.

有两种类型的 MSR 由 TDX 模块控制：

- 直通 MSR（直接从 CPU 读取/写入，例如与侧信道相关的 MSR，例如 ARCH_CAPABILITIES）

- 禁止的 MSR，尝试读取/写入此类 MSR 会导致 #GP（例如，所有 IA32_VMX_* KVM MSR）。

所有这些 MSR 都由平台控制，是可信的，不需要任何加固。有关确切列表，请参见 Intel TDX 模块架构规范 <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>_ 的第 18.1 节。



MSRs proxied through TDVMCALL and controlled by host
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Access to these MSRs typically results in a #VE event inserted by the TDX module
back to the TDX guest, and the TDX guest kernel #VE handler invoking the TDVMCALL
hypercall to the untrusted VMM to obtain/set these MSR values. In some cases
for performance reasons the TDVMCALL hypercall is invoked directly from TDX guest
kernel to avoid an additional context switch to the TDX module.
All these MSRs are considered untrusted and their handling in the TDX guest kernel
must be hardened, i.e., audited and fuzzed using the methodology described in
:ref:`tdx-guest-hardening`.

Based on our fuzzing and auditing activities, the risk for the memory
safety issues based on MSR values is considered to be low, since most of the MSRs
are handled via masking individual MSR bits, i.e., saving and restoring MSR bit values.
However, some MSRs control rather complex functionality, such as
IA32\_MC*, IA32\_MTRR\_*, IA32\_TME\_*.
We have disabled most of such features to minimize the exposed attack
surface via clearing the following feature bits during TDX guest early
initialization: X86\_FEATURE\_MCE, X86\_FEATURE\_MTRR, X86\_FEATURE\_TME.
For the full up-to-date list, please check tdx_early_init() function.
Should these feature need to be enabled, a detailed code audit and fuzzing
approach must be used to ensure the respective code is hardened.


访问这些 MSR 通常会导致 TDX 模块将 #VE 事件插入回 TDX 客户端，TDX 客户端内核 #VE 处理程序调用 TDVMCALL 超级调用向不受信任的 VMM 获取/设置这些 MSR 值。在某些情况下，为了性能原因，TDVMCALL 超级调用直接从 TDX 客户端内核调用，以避免与 TDX 模块的额外上下文切换。所有这些 MSR 都被认为是不受信任的，它们在 TDX 客户端内核中的处理必须加固，即使用 :ref:tdx-guest-hardening 中描述的方法进行审计和模糊测试。

根据我们的模糊测试和审计活动，基于 MSR 值的内存安全问题的风险被认为很低，因为大多数 MSR 都是通过屏蔽单个 MSR 位来处理的，即保存和恢复 MSR 位值。然而，一些 MSR 控制相当复杂的功能，例如 IA32_MC*、IA32_MTRR_、IA32_TME_。我们已经禁用大多数此类功能，以最大程度地减少通过在 TDX 客户端早期初始化期间清除以下功能位来暴露的攻击面：X86_FEATURE_MCE、X86_FEATURE_MTRR、X86_FEATURE_TME。有关最新列表，请查看 tdx_early_init() 函数。如果需要启用这些功能，则必须使用详细的代码审计和模糊测试方法来确保相应的代码得到加固。

.. _sec-io-ports:

IO ports
--------

IO ports are controlled by the host and could be an attack vector.

All IO port accesses go through #VE or direct TDVMCALLs. We’ll use a
small allow list of trusted ports. This helps to prevent the host from trying to
inject old ISA drivers that use port probing and might have
vulnerabilities processing port data. While normally these cannot be
auto loaded, they might be statically compiled into kernels and would do
standard port probing.

The most prominent user is the serial port driver. Using the serial port
(e.g. for early console) requires disabling security. In the secure mode
we only have the virtio console.

IO 端口由主机控制，可能成为攻击向量。

所有 IO 端口访问都通过 #VE 或直接 TDVMCALL 进行。我们将使用一个小的受信任端口允许列表。这有助于防止主机尝试注入使用端口探测的旧 ISA 驱动程序，并可能在处理端口数据时存在漏洞。虽然通常这些驱动程序无法自动加载，但它们可能会静态编译到内核中，并进行标准端口探测。

最显著的用户是串行端口驱动程序。使用串行端口（例如用于早期控制台）需要禁用安全模式。在安全模式下，我们只有 virtio 控制台。

The table below shows the allow list ports in the current TDX guest
kernel:

.. list-table:: List ports
   :widths: 7 7 10
   :header-rows: 1


   * - Port range
     - Intended user
     - Comments
   * - 0x70 … 0x71
     - MC146818 RTC
     -
   * - 0xcf8 … 0xcff
     - PCI config space
     - Ideally this range should be further limited since likely not being
       needed in full
   * - 0x600 ... 0x62f
     - ACPI ports
     - 0600-0603 : ACPI PM1a\_EVT\_BLK
       0604-0605 : ACPI PM1a\_CNT\_BLK
       0608-060b : ACPI PM\_TMR
       0620-062f : ACPI GPE0\_BLK
   * - 0x3f8, 0x3f9,0x3fa, 0x3fd
     - COM1 serial
     - Only in debugmode

IO port accesses for the TDX guest userspace (ring 3) are not supported
and results in SIGSEGV.

.. _sec-kvm-hypercalls:

KVM CPUID features and Hypercalls
---------------------------------

For various performance enhancements KVM provides a number of PV features
towards its guests that are enumerated via KVM CPUIDs. Some of these features
define respected KVM hypercalls, and some are using other means for communication:
MSRs, memory structures, etc. Each of such features is under full control of
the host and should be considered untrusted. KVM hypercalls are proxied through
TDVMCALL in TDX case. For the full list of KVM features and hypercalls please consult 
`KVM CPUIDs <https://www.kernel.org/doc/Documentation/virt/kvm/cpuid.rst>`_ 
and `KVM hypercalls description <https://www.kernel.org/doc/Documentation/virt/kvm/hypercalls.rst>`_ .

Based on our security analysis (see `Security implications from KVM PV features <https://github.com/intel/ccc-linux-guest-hardening/issues/152>`_ 
for more information), only the KVM\_FEATURE\_CLOCKSOURCE(2) CPUIDs
should be explicitly disabled in the guest kernel, since it would allow the
guest to rely on host-controlled kvmclock for providing the timing information. The disabling
can be done via "no-kvmclock" guest kernel cmdline option. 
The rest of features do not require explicit disabling, because they
either considered not to have any security implications towards the TDX
guest (apart from DoS) or already indirectly disabled (KVM_FEATURE_ASYNC_PF,
KVM_FEATURE_PV_EOI, KVM_FEATURE_STEAL_TIME) because the required memory structures
are not shared between the host and the guest.

为实现各种性能增强，KVM 向其客户提供了一些通过 KVM CPUID 枚举的 PV 特性。这些特性中的一些定义了相应的 KVM hypercalls，一些使用其他方式进行通信：MSR、内存结构等。每个这样的特性都完全由主机控制，应被视为不受信任。在 TDX 的情况下，KVM hypercalls 通过 TDVMCALL 代理。有关 KVM 特性和 hypercalls 的完整列表，请参阅 KVM CPUIDs 和 KVM hypercalls 说明。

根据我们的安全分析（有关更多信息，请参阅 Security implications from KVM PV features），仅 KVM_FEATURE_CLOCKSOURCE(2) CPUID 应在客户内核中显式禁用，因为它允许客户依赖于主机控制的 kvmclock 来提供时间信息。可以通过 "no-kvmclock" 客户内核命令行选项进行禁用。其他特性不需要显式禁用，因为它们要么被认为对 TDX 客户没有安全影响（除了 DoS 之外），要么已经间接禁用（KVM_FEATURE_ASYNC_PF、KVM_FEATURE_PV_EOI、KVM_FEATURE_STEAL_TIME），因为所需的内存结构未在主机和客户之间共享。
 
 .. _sec-cpuids:

CPUID
-----

Reading untrusted CPUIDs could be used to let the guest kernel execute
non-hardened code paths. The TDX module ensures that most CPUID values
are trusted (see section 18.2 in `Intel TDX module architecture specification <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>`_), but some are configurable
via the TD\_PARAMS structure or can be provided by the untrusted
host/VMM via the logic implemented in the #VE handler.

Since the TD\_PARAMS structure is measured into TDX measurement
registers and can be attested later, the CPUID bits that are configured
using this structure can be considered trusted.

The table below lists the CPUID leaves that result in a #VE inserted by
the TDX module. 


读取不受信任的 CPUID 可能会让客户内核执行未加固的代码路径。TDX 模块确保大多数 CPUID 值是可信的（参见 Intel TDX 模块架构规范 的第 18.2 节），但某些值可以通过 TD_PARAMS 结构配置或通过 #VE 处理程序中实现的逻辑由不受信任的主机/VMM 提供。

由于 TD_PARAMS 结构被测量到 TDX 测量寄存器中，可以在稍后进行证明，因此使用此结构配置的 CPUID 位可以被视为可信的。

以下表格列出了 TDX 模块插入的 #VE 事件的 CPUID 叶子。


.. list-table:: CPUID leaves
   :widths: 15 20 40
   :header-rows: 1

   * - Cpuid Leaf
     - Purpose
     - Comment
   * - 0x2
     - Cache & TLB info
     - Obsolete leaf, code will prefer CPUID 0x4 which is trusted
   * - 0x5
     - Monitor/Mwait
     -
   * - 0x6
     - Thermal & Power Mgmt
     -
   * - 0x9
     - Direct cache access info
     -
   * - 0xb
     - Extended topology enumeration
     -
   * - 0xc
     - Reserved
     - Not used in Linux
   * - 0xf
     - Platform QoS monitoring
     - Explicitly disabled in TDX guest via clearing X86\_FEATURE\_CQM\_LLC
       feature bit
   * - 0x10
     - Platform QoS Enforcement
     - Explicitly disabled in TDX guest via clearing X86\_FEATURE\_MBA
       feature bit
   * - 0x16
     - Processor frequency
     - The only user of this cpuid in the TDX guest is
       cpu\_khz\_from\_cpuid, but the TDX guest code has been changed to
       first use cpuid leaf 0x15 which is guaranteed by the TDX module
   * - 0x17
     - SoC Identification
     -
   * - 0x18
     - TLB Deterministic Parameters
     -
   * - 0x1a
     - Hybrid Information
     -
   * - 0x1b
     - MK TME
     - Explicitly disabled in TDX guest via clearing X86\_FEATURE\_TME
       feature bit
   * - 0x1f
     - V2 Extended Topology Enumeration
     -
   * - 0x80000002-4
     - Processor Brand String
     -
   * - 0x80000005
     - Reserved
     -
   * - 0x80000006
     - Cache parameters
     -
   * - 0x80000007
     - AMD Advanced Power Management
     -
   * - 0x40000000- 0x400000FF
     - Reserved for SW use
     -



Most of the above CPUID leaves result in different feature bits and
therefore are harmless. The ones that have larger fields have been
audited and fuzzed in the same way as other untrusted inputs from the
hypervisor. In addition, it is also possible to sanitize multi-bit
CPUIDs against the bounds expected for a given platform.

However, to strengthen security even further, the #VE handler in TDX
guest kernel has been recently modified to only allow leaves in the
range 0x40000000 - 0x400000FF to be requested from the untrusted host/VMM.
If SW inside TDX guest tries to read any other leaf from the above table,
the value of 0 is returned.

以上大多数 CPUID 叶子导致不同的特性位，因此是无害的。具有较大字段的那些已按照与其他不受信任输入的同样方式进行了审计和模糊测试。此外，还可以根据给定平台的预期范围对多位 CPUID 进行消毒。

然而，为了进一步加强安全性，TDX 客户端内核中的 #VE 处理程序已被修改为仅允许请求范围为 0x40000000 - 0x400000FF 的叶子。如果 TDX 客户端内的软件尝试读取上述表中的任何其他叶子，则返回值为 0。

Perfmon
-------

For CPUID, see `KVM CPUID`_ above.

For MSR, see `MSRs`_ .

The uncore drivers are explicitly disabled with a hypervisor check,
since they generally don’t work in virtualization of any kind. This
includes the architectural Chassis perfmon discovery, which works using
MMIO.

有关 CPUID，请参阅 KVM CPUID。

有关 MSR，请参阅 MSRs。

未核驱动程序通过 hypervisor 检查显式禁用，因为它们通常不适用于任何形式的虚拟化。这包括使用 MMIO 的架构性底盘性能监控发现。



IOMMU
=========

IOMMU is disabled for the TDX guest due to the DMAR ACPI table not being
included in the list of allowed ACPI tables for the TDX guest. Similar
for the AMD IOMMU. The other IOMMU drivers should not be active on x86.

由于 DMAR ACPI 表未包含在 TDX 客户的允许 ACPI 表列表中，因此 IOMMU 对于 TDX 客户被禁用。对于 AMD IOMMU 也是如此。其他 IOMMU 驱动程序不应在 x86 上激活。



 .. _sec-randomness:

Randomness inside TDX guest
===========================

Linux RNG
---------

The Linux RNG uses timing from interrupts as the default entropy source;
this can be a problem for the TDX guest because timing of the interrupts
is controlled by the untrusted host/VMM. However, on x86 platforms there
is another entropy source that is outside of host/VMM control: RDRAND/RDSEED
instructions. The commit `x86/coco: Require seeding RNG with RDRAND on CoCo systems <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/arch/x86/coco/core.c?h=v6.9-rc5&id=99485c4c026f024e7cb82da84c7951dbe3deb584>`_ ensures that a TDX guest
cannot boot unless 256 bits of RDRAND output is mixed into the entropy pool
early during the boot process. 

Linux RNG 使用中断的时间作为默认熵源；这对于 TDX 客户可能是一个问题，因为中断的时间由不受信任的主机/VMM 控制。然而，在 x86 平台上，还有一个不受主机/VMM 控制的熵源：RDRAND/RDSEED 指令。提交 x86/coco: Require seeding RNG with RDRAND on CoCo systems 确保 TDX 客户不能启动，除非在启动过程的早期将 256 位的 RDRAND 输出混入熵池中。


 .. _sec-time:

TSC and other timers
=====================

TDX has a limited secure time with the TSC timer. The TSC inside a TD is
guaranteed to be synchronized and monotonous, but not necessarily
matching real time. A guest can turn it into truly secure wall time by
using a remote authenticated time server. This is the recommended way of
obtaining the secure time inside a TDX guest. In the absence of a 
remote authenticated server, TDX guest gets the time from Linux RTC.
However, Linux RTC has not yet been hardened and its usage presents a
potential security threat.

By default, for the KVM hypervisor, kvmclock would have priority, which
is not secure anymore because it uses untrusted input from the host. To
avoid this the kvmclock must be disabled by using 'no-kvmclock' cmdline
option (command line is measured and can be attested).
Additionally, the TSC watchdog is also disabled (by
forcing the X86\_FEATURE\_TSC\_RELIABLE bit) to avoid the possible
fallback to jiffy time, which could be influenced by the host by
changing the frequency of the timer interrupts.

The TSC deadline timer inside the TDX guest is not secure and fully under
the control of host/VMM. The TSC deadline feature enumeration (CPUID(1).ECX[24])
inside the TDX guest reports the platform native value, but the TDX guest kernel
reads or writes to MSR_IA32_TSC_DEADLINE will result in a #VE
inserted to the guest and in a subsequent TDVMCALL to VMM. On such a call the VMM starts
an LAPIC timer to emulate tsc deadline timer and inject a posted interrupt
to the TDX guest when the timer expires.

TDX 具有有限的安全时间，使用 TSC 定时器。TD 中的 TSC 保证是同步的和单调递增的，但不一定与实际时间匹配。客户可以通过使用远程认证时间服务器将其转换为真正安全的壁钟时间。这是获取 TDX 客户内部安全时间的推荐方式。在没有远程认证服务器的情况下，TDX 客户从 Linux RTC 获取时间。然而，Linux RTC 尚未加固，其使用存在潜在的安全威胁。

默认情况下，对于 KVM hypervisor，kvmclock 具有优先级，这不再安全，因为它使用来自主机的不受信任输入。为避免这种情况，必须通过使用“no-kvmclock”命令行选项禁用 kvmclock（命令行已被测量并可进行证明）。此外，TSC 看门狗也被禁用（通过强制设置 X86_FEATURE_TSC_RELIABLE 位）以避免可能的回退到 jiffy 时间，这可能会通过改变计时器中断的频率来受到主机的影响。

TDX 客户端中的 TSC 期限定时器不安全，完全由主机/VMM 控制。TDX 客户端中的 TSC 期限特性枚举（CPUID(1).ECX[24]）报告平台本地值，但 TDX 客户端内核对 MSR_IA32_TSC_DEADLINE 的读取或写入将导致向客户插入 #VE，并随后的 TDVMCALL 到 VMM。在这样的调用中，VMM 启动 LAPIC 计时器来模拟 TSC 期限定时器，并在计时器到期时向 TDX 客户端注入一个已发布的中断。



Declaring insecurity to user space
==================================

Many of the security measures described in this document can be disabled
with command line arguments, especially any kind of filtering. While
such a configuration change is detected by attestation, there are use
cases that don’t use full attestation and may continue running even if
it fails.

For this purpose, a taint flag TAINT\_CONF\_NO\_LOCKDOWN is set when any
command line overrides for lockdowns are used. The user agent could
check that by using /proc/sys/kernel/taint. Additionally, there are
warnings printed to indicate whenever the device filter has been
disabled, overridden over command line, etc.

The key server helps to ensure through attestation that the guest runs in secure
mode. It does that by attesting the kernel command line, as well as the
kernel binary. The kernel configuration should include module signing,
which can be enforced by the command line as well as the binary.


本文档中描述的许多安全措施可以通过命令行参数禁用，尤其是任何类型的过滤。虽然这样的配置更改可以通过证明检测到，但有些用例不使用完整的证明，即使失败也可能继续运行。

为此，当使用命令行覆盖 lockdowns 时，将设置 taint 标志 TAINT_CONF_NO_LOCKDOWN。用户代理可以通过使用 /proc/sys/kernel/taint 来检查这一点。此外，还有警告指示设备过滤器何时被禁用、通过命令行覆盖等。

密钥服务器通过证明确保客户在安全模式下运行。它通过证明内核命令行以及内核二进制文件来实现这一点。内核配置应包括模块签名，可通过命令行以及二进制文件强制执行。

.. _sec-acpi-tables:

BIOS-supplied ACPI tables and mappings
======================================

ACPI table mappings and similar table mappings use the ioremap\_cache
interface, which is never set to 'shared' with the untrusted host/VMM.
However, in order to be able to share operating regions declared in
ACPI tables a new interface ioremap\_cache\_shared is introduced. This
interface sets the pages to shared and is currently only used by the
acpi system memory address space handler (acpi\_ex\_system\_memory\_space\_handler).
Note that this means that any operating region declared in the allow
list of TDX guest kernel ACPI tables is going to be set to 'shared' automatically.
This further motivates keeping the allowed ACPI table list in TDX guest
to a minimum required amount, and auditing the content of the allowed
tables. Ideally it would be more secure to only share operating regions
of drivers authorized by the device filter. However, since ACPI core doesn't
have a mapping between operating region addresses and the drivers that requested it,
this change has been proven to be too intrusive. 

ACPI tables are (mostly) controlled by the host and only passed through
the TDVF (see `TDX guest virtual firmware <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-virtual-firmware-design-guide-rev-1.01.pdf>`_ for more information).
They are measured into TDX attestation registers, and therefore can be
remotely attested and therefore can be considered trusted. However, we
cannot expect that an attesting entity fully understands what causes the
Linux kernel to open security holes based on some particular AML. Then a
malicious hypervisor might be able to attack the guest based on attack
surfaces exposed by the non-malicious and attested ACPI tables. The main
concern here is the tables and methods that configure some functionality
in the kernel, such as initializing drivers.

As a first step to minimize the above attack surface, the TDX guest
kernel defines an allow list for the ACPI tables. Currently the list
includes the following tables: XSDT, FACP, DSDT, FACS, APIC, and SVKL.
However, it still includes large tables like DSDT that contain a lot of
functionality. Ideally one would need to define a minimal set of methods
that such table needs to support and then perform a code audit and
fuzzing of these methods. All features that are not required (for
example CPPC throttling) should be disabled to minimize the attack
surface. This hardening activity has not been performed for the TDX
guest and remains a future task. Alternatively, for a more generic
hardening in-depth approach, the whole ACPI interpreter can be fuzzed
and hardened, but this is a considerable effort and also is left for the
future. For example, one possible future hardening is to add some range
checking in ACPI to not write from AML to memory outside MMIO.

ACPI 表映射和类似表映射使用 ioremap_cache 接口，该接口从未设置为与不受信任的主机/VMM 共享。然而，为了能够共享在 ACPI 表中声明的操作区域，引入了一个新接口 ioremap_cache_shared。此接口将页面设置为共享，目前仅由 acpi 系统内存地址空间处理程序（acpi_ex_system_memory_space_handler）使用。请注意，这意味着 TDX 客户端内核 ACPI 表允许列表中的任何操作区域声明将自动设置为“共享”。这进一步推动了将 TDX 客户端内核中的允许 ACPI 表列表保持在最少的要求数量，并审核允许表的内容。理想情况下，最安全的做法是只共享由设备过滤器授权的驱动程序的操作区域。然而，由于 ACPI 核心没有操作区域地址与请求它的驱动程序之间的映射，这种更改被证明过于侵入。

ACPI 表（大多数情况下）由主机控制，并且仅通过 TDVF 传递（有关更多信息，请参阅 TDX 客户端虚拟固件）。它们被测量到 TDX 证明寄存器中，因此可以进行远程证明，因此可以被视为可信。然而，我们不能期望证明实体完全理解 Linux 内核如何根据某些特定的 AML 造成安全漏洞。然后恶意的 hypervisor 可能能够基于无恶意的经过证明的 ACPI 表所暴露的攻击面来攻击客户。这里的主要问题是配置内核中某些功能的表和方法，例如初始化驱动程序。

作为减少上述攻击面的第一步，TDX 客户内核定义了 ACPI 表的允许列表。目前，该列表包括以下表：XSDT、FACP、DSDT、FACS、APIC 和 SVKL。然而，它仍然包含像 DSDT 这样的大表，包含大量功能。理想情况下，需要定义这样的表需要支持的方法的最小集合，然后对这些方法进行代码审计和模糊测试。所有不需要的功能（例如 CPPC 节流）都应禁用，以最大程度地减少攻击面。此硬化活动尚未对 TDX 客户端进行，仍然是未来的任务。或者，为了更通用的深入硬化，可以对整个 ACPI 解释器进行模糊测试和硬化，但这是一个相当大的工作量，也留待将来进行。例如，未来可能的硬化之一是在 ACPI 中添加一些范围检查，以防止 AML 写入超出 MMIO 的内存。


TDX guest private memory page management
========================================

All TDX guest private memory pages are allocated by the host and must be
explicitly “accepted” into the guest using the TDG.MEM.PAGE.ACCEPT command. The TDX
guest kernel needs to make sure that an already accepted page is not
accepted again, because doing so would change the content of the guest
private page to a zero page with possible security implications (zeroing
out keys, secrets, etc.). Additionally, per current design of the TDX
module, certain events (like TDX guest memory access to a non-accepted page)
can result in a #VE event inserted by the TDX guest module. Please see section 16.3.3 in
`Intel TDX module architecture specification <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>`_ for more details.
The guest kernel must always check the cause of a #VE event and panic if
it sees a #VE event that is caused by access to a TDX guest private page.
If this check is not implemented, it opens a TDX guest to many attacks against
the content of the TDX guest private memory. 
For the Linux guest kernel specifically, it is also very important that such #VE notifications do
not happen during certain TDX guest critical code paths. The section `Safety against #VE in kernel code`_ 
provides more details, as well as describes how Linux guest kernel avoids
#VE events altogether.

所有 TDX 客户端私有内存页面由主机分配，必须使用 TDG.MEM.PAGE.ACCEPT 命令显式“接受”到客户中。TDX 客户端内核需要确保已经接受的页面不会再次接受，因为这样做会将客户私有页面的内容更改为零页面，可能会产生安全影响（清除密钥、秘密等）。此外，根据 TDX 模块的当前设计，某些事件（例如 TDX 客户内存访问未接受的页面）可能会导致由 TDX 客户模块插入的 #VE 事件。有关更多详细信息，请参阅 Intel TDX 模块架构规范 的第 16.3.3 节。客户内核必须始终检查 #VE 事件的原因，如果看到由访问 TDX 客户私有页面引起的 #VE 事件，则会出现恐慌。如果没有实施此检查，它将对 TDX 客户私有内存的内容发起许多攻击。对于 Linux 客户端内核来说，尤其重要的是，在某些 TDX 客户端关键代码路径期间不发生此类 #VE 通知。Safety against #VE in kernel code 一节提供了更多详细信息，并描述了 Linux 客户端内核如何完全避免 #VE 事件。



TDVF conversion
---------------

Most of the initial memory for the TDX guest is converted by the TDVF
and the TDX guest kernel can use all this memory through the normal UEFI
memory map. However, due to performance implications, it is not possible
to pre-accept all memory required for a guest to run, so the lazy memory
accept logic described the next section is used.

大多数初始内存由 TDVF 转换，TDX 客户端内核可以通过正常的 UEFI 内存映射使用所有这些内存。然而，由于性能影响，不可能预先接受客户运行所需的所有内存，因此使用下一节中描述的惰性内存接受逻辑。

Lazy conversion
---------------

To address the significant performance implications of pre-accepting all
the pages, the pages will be accepted in runtime as required. Once VMM
adds a private memory page to a TDX guest, its secure EPT entry resides
in the PENDING state before the TDX guest explicitly accepts this page
(secure EPT entry moves to PRESENT state) using the TDG.MEM.PAGE.ACCEPT
instruction.

According to the `Intel TDX module architecture specification <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>`_, if the TDX guest attempts to
accept the page that is already in the PRESENT state (essentially do a
double accept by chance), then the TDX module has a way to detect this
and supply a warning, so accepting an already accepted page is OK.

However, it is possible that that malicious host/VMM can execute the
sequence of TDH.MEM.RANGE.BLOCK; TDH.MEM.TRACK; and TDH.MEM.PAGE.REMOVE
calls on any present private page. Then it can quickly add it back with
TDH.MEM.PAGE.AUG, and it goes into pending state. If the guest does not
verify that it has previously accepted this page and accepts it again,
it would end up using a zero page instead of data it previously had
there. So, re-accept can happen if there is no TDX guest internal
tracking of which pages have been previously accepted. For this purpose,
the TDX guest kernel keeps track of already accepted pages in a 2MB
granularity bitmap allocated in decompressor. In turn the page allocator
accepts 2MB chunks as needed.


为解决预先接受所有页面的显着性能影响，页面将在运行时按需接受。一旦 VMM 向 TDX 客户添加了一个私有内存页面，它的安全 EPT 条目在 TDX 客户明确接受此页面之前处于 PENDING 状态（安全 EPT 条目移动到 PRESENT 状态），使用 TDG.MEM.PAGE.ACCEPT 指令。

根据 Intel TDX 模块架构规范，如果 TDX 客户尝试接受已经处于 PRESENT 状态的页面（实质上是偶然进行二次接受），则 TDX 模块有办法检测到这一点并发出警告，因此接受已经接受的页面是可以的。

但是，可能发生的是恶意主机/VMM 可以对任何当前的私有页面执行 TDH.MEM.RANGE.BLOCK；TDH.MEM.TRACK；和 TDH.MEM.PAGE.REMOVE 调用。然后它可以快速使用 TDH.MEM.PAGE.AUG 添加它，并且它进入待处理状态。如果客户不验证它以前是否接受过该页面并再次接受它，它将最终使用零页面而不是先前在那里拥有的数据。因此，如果没有 TDX 客户端跟踪已接受的页面，可能会发生重新接受。为此，TDX 客户端内核在解压程序中分配的 2MB 粒度位图中跟踪已接受的页面。反过来，页面分配器会在需要时接受 2MB 的块。


Safety against #VE in kernel code
---------------------------------

The TDX guest Linux kernel needs to make sure it does not get #VE in certain critical
sections. One example of such a section is a system call gap: on
SYSCALL/SYSRET. There is a small instruction window where the kernel
runs with the user stack pointer. If a #VE event (for example due to a
malicious hypervisor removing a memory page as explained in the above
section) happens in that window, it would allow a malicious userspace
(ring 3) process in the guest to take over the guest kernel. As a result,
it must be ensured that it is not possible to get a #VE event on the
pages containing kernel code or data.

Such #VE events are currently possible in two cases:

1. TD guest accesses a private GPA for which the Secure EPT entry is in PENDING state and ATTRIBUTES.SEPT\_VE\_DISABLE TD guest attribute is not set.
2. TDX module can raise a #VE as a notification mechanism when it detects excessive Secure EPT violations raised by the same TD instruction (zero-step attack is detected by TDX module). This is only done if bit 0 of TDCS.NOTIFY\_ENABLES field is set. 

To ensure the above situations do not occur, the TD Linux guest kernel
performs the following during kernel initialization:

1. Checks that ATTRIBUTES.SEPT\_VE\_DISABLE is set and panic otherwise.
2. Forcefully clear the TDCS.NOTIFY\_ENABLES bit 0 regardless of its state. 

Although the later check disables TDX module notifications for excessive numbers
of Secure EPT violations, the basic defenses against zero-stepping
provided by the TDX module are still in effect.
For more details please see section 16.3 in
`Intel TDX module architecture specification <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>`_


TDX 客户端 Linux 内核需要确保在某些关键部分不会收到 #VE。此类部分的一个示例是系统调用间隙：在 SYSCALL/SYSRET 上。有一个小的指令窗口，其中内核使用用户堆栈指针运行。如果在该窗口中发生 #VE 事件（例如，由于恶意 hypervisor 删除了一个内存页面，如上述部分所解释的那样），它将允许恶意的用户空间（ring 3）进程接管客户内核。因此，必须确保在包含内核代码或数据的页面上不可能发生 #VE 事件。

目前在两种情况下可能会发生此类 #VE 事件：

1. TD 客户端访问安全 EPT 条目处于 PENDING 状态且 ATTRIBUTES.SEPT_VE_DISABLE TD 客户端属性未设置的私有 GPA。
2. 当 TDX 模块检测到由同一 TD 指令引发的过多安全 EPT 违规时，TDX 模块可以将 #VE 作为通知机制提出。这仅在设置了 TDCS.NOTIFY_ENABLES 字段第 0 位时执行。

为了确保上述情况不会发生，TD Linux 客户端内核在内核初始化期间执行以下操作：

1. 检查是否设置了 ATTRIBUTES.SEPT_VE_DISABLE，并且如果未设置，则会出现 panic。
2. 无论其状态如何，强制清除 TDCS.NOTIFY_ENABLES 第 0 位。


尽管后面的检查禁用了 TDX 模块的通知，以防止过多的安全 EPT 违规，但 TDX 模块提供的针对零步攻击的基本防御仍然有效。
有关更多详细信息，请参阅 Intel TDX 模块架构规范 的第 16.3 节。

Reliable panic
==============

In various situations when the TDX guest kernel detects a potential
security problem, it needs to reliably stop. Standard panic performs
many complex actions:

1. IPIs to other CPUs to stop them. This is not secure because the IPI
   is controlled by the host, which could choose not to execute them.

2. There can be notifiers to other drivers and subsystems which can do
   complex actions, including something that would cause the panic to
   wait for a host action.

As a result, it is not possible to guarantee that any other VCPU is
reliably stopped with the standard panic and therefore a reliable panic
is required. There is a potential path to make the panic more atomic
(prevent reentry), but not fully atomic (due to TDX module limitations).
This remains to be a direction for future work.

在 TDX 客户端内核检测到潜在的安全问题时，它需要可靠地停止。标准的 panic 执行许多复杂的操作：

1. IPI 其他 CPU 以停止它们。这不安全，因为 IPI 由主机控制，主机可以选择不执行它们。

2. 可能会有通知到其他驱动程序和子系统，这些驱动程序和子系统可以执行复杂的操作，包括可能导致 panic 等待主机操作的操作。

因此，不能保证使用标准的 panic 可靠地停止任何其他 VCPU，因此需要可靠的 panic。有可能使 panic 更加原子化（防止重入），但不是完全原子化（由于 TDX 模块的限制）。这仍然是未来的工作方向。


Kernel and initrd loading
=========================

In a simple reference configuration the TDVF loads the kernel,
the initrd, and a startup script from an
unencrypted UEFI VFAT volume in the guest storage area through virtio.
The startup script contains the kernel command line. The kernel is
booted through the Linux UEFI stub. Before booting the TDVF runs hashes
over the kernel image/initrd/startup script and attest those to a key
server through the TDX measurement registers.

在简单的参考配置中，TDVF 通过 virtio 从客户存储区中的未加密 UEFI VFAT 卷加载内核、initrd 和启动脚本。启动脚本包含内核命令行。内核通过 Linux UEFI stub 引导。在引导之前，TDVF 会对内核镜像/initrd/启动脚本运行哈希，并通过 TDX 测量寄存器向密钥服务器证明这些哈希。



.. _sec-kernel-cmd:

Kernel command line
===================

The kernel command line will allow to run an insecure kernel by
disabling various security features or injecting unsafe code. However,
we assume that the kernel command line is trusted, which is ensured by
measuring its contents by the TDVF into TDX attestation registers.

The following command options are currently supported by TD guest kernel:

1. **tdx_disable_filter**. This option completely turns off the TDX
device filter: guest kernel will allow loading of arbitrary device drivers
in this mode. Additionally, a lot of explicitly disabled functionally
(like pci quirks, enhanced pci capabilities, pci bridge support and others),
will no longer be disabled and the respected unhardened linux guest code
becomes reachable for the interaction with an untrusted host/VMM.
For more detailed information on what functionality is guarded by the TDX
device filter, see conditional checks cc_platform_has(CC_ATTR_GUEST_DEVICE_FILTER)
in the kernel source code. Note that the port IO filter is also disabled in this mode.
As a result, passing tdx_disable_filter option via TD guest command line
enables a lot of unhardened code in the attack surface between an untrusted
host/VMM and TDX Linux guest kernel. The remote attester must always verify
that this option has not been used to start a TDX guest kernel via the TDX
attestation quote.

2. **authorize_allow_devs=**. This option allows to specify a list of allowed
devices in addition to the explicit list specified by TDX filter. However,
this option is only intended for the debug purpose and should not be used
in production since there is a high risk to enable devices this way that
haven't been hardened to withstand a potentially malicious host input.
Instead, when a new device needs to be added to the TDX filter default allow
list, the steps from `Enabling additional kernel drivers <https:TBD>`_ must
be followed. 

3. **tdx_allow_acpi=**. This option allows passing additional allowed acpi
tables to the default list specified in the TDX filter. Similarly, as the
above option, it should be only used for the debug purpose. If an
additional acpi table needs to be used in TDX guest, it should be included
in the default TDX filter list after a security audit and risk assessment.


内核命令行将允许通过禁用各种安全功能或注入不安全代码来运行不安全的内核。然而，我们假设内核命令行是可信的，这是通过 TDVF 将其内容测量到 TDX 证明寄存器中来确保的。

目前，TD 客户内核支持以下命令选项：

tdx_disable_filter。此选项完全关闭 TDX 设备过滤器：在此模式下，客户内核将允许加载任意设备驱动程序。此外，显式禁用的许多功能（如 pci quirks、增强的 pci 功能、pci 桥支持等）将不再被禁用，并且相关的未加固的 linux 客户代码将变得可访问，以与不受信任的主机/VMM 进行交互。有关 TDX 设备过滤器保护哪些功能的详细信息，请参阅内核源代码中的条件检查 cc_platform_has(CC_ATTR_GUEST_DEVICE_FILTER)。请注意，在此模式下，端口 IO 过滤器也被禁用。因此，通过 TD 客户命令行传递 tdx_disable_filter 选项会在不受信任的主机/VMM 和 TDX Linux 客户端内核之间启用大量未加固的代码攻击面。远程证明者必须始终验证未使用此选项启动 TDX 客户端内核，方法是通过 TDX 证明引用。

authorize_allow_devs=。此选项允许指定除 TDX 过滤器明确指定的明确列表之外的设备列表。但是，此选项仅用于调试目的，不应在生产中使用，因为有很高的风险启用此方式的设备尚未加固以抵御潜在的恶意主机输入。相反，当需要向 TDX 过滤器默认允许列表添加新设备时，必须遵循 Enabling additional kernel drivers 中的步骤。

tdx_allow_acpi=。此选项允许向 TDX 过滤器中指定的默认列表传递其他允许的 acpi 表。与上述选项类似，它应该仅用于调试目的。如果需要在 TDX 客户中使用其他 acpi 表，则应在安全审计和风险评估后将其包含在默认 TDX 过滤器列表中。


Additionally, to minimize the attack surface the following cmdline options
are strongly recommended for TDX guests:



.. list-table:: cmdline options
   :widths: 20 60
   :header-rows: 1

   * - cmdline option
     - Purpose
   * - mce=off
     - Disables unneeded MCE/MCA subsystem, which hasn't been hardened
   * - oops=panic
     - Enables panic on oops, generic security mechanism to harden kernel
   * - pci=noearly
     - Disables unneeded early pci subsystem, which hasn't been hardened 
   * - pci=nommconf
     - Disables memory mapped pci config space, which hasn't been used so
       far in TDX guests
   * - no-kvmclock
     - Disables kvm-clock as untrusted time source
   * - random.trust_cpu=y
     - Trusts architecture-provided DRNG (RDRAND/RDSEED on intel platforms)
       to provide enough entropy during early boot
   * - random.trust_bootloader=n
     - Disables crediting entropy obtained from the bootloader via
       add_bootloader_randomness. 

Storage protection
==================

The confidentiality and authenticity of the TD guest disk volume’s needs
to be protected from the host/VMM that handles it. The exact protection
method is decided by the TD tenant, but we provide a default reference
setup. We use dmcrypt with LUKS with dm integrity to provide encryption
and authentication for the storage volumes. To retrieve the decryption
key during the TD boot process, the TD guest initrd contains an agent
that performs the TD attestation to a remote key server. The attestation
quote is going to contain the measurements from the TDVF, the boot
loader, kernel, its command line, and initrd itself. The actual
communication protocol between the remote key server and the initrd
attestation agent will be customer (cloud) specific. The reference
initrd attestation agent provided by Intel implements the Intel
reference protocol. After the attestation succeeds, the initrd
attestation agent obtains the key and it is used by the initrd to mount
the TD guest file system.

Users could use other encryption schemes for storage, such as not using
LUKS but some other encrypted storage format. Alternatively, they could
also not use local storage and rely on a volume mounted from the network
after attesting themselves to the network server. However, support for
such remote storage is out of the scope for this document for now.

*Note*: Commonly used read/write Linux storage protection methods (including
dmcrypt and dm integrity) do not provide rollback protection.
If rollback attacks are a concern, the networking-based storage outside
of attacker control is the recommended option. The absence of rollback
protection also has implications on guest private memory rollback attacks
if memory swapping to the filesystem is enabled in the guest kernel. 
Due to this limitation, we recomend disabling guest memory swap. 

TD 客户端磁盘卷的机密性和真实性需要得到处理它的主机/VMM 的保护。确切的保护方法由 TD 租户决定，但我们提供了一个默认的参考设置。我们使用带有 dm 完整性 dmcrypt 和 LUKS 来提供存储卷的加密和身份验证。要在 TD 启动过程中检索解密密钥，TD 客户端 initrd 包含一个代理，该代理对远程密钥服务器执行 TD 证明。证明引用将包含 TDVF、引导加载程序、内核及其命令行和 initrd 本身的测量值。TD 证明成功后，initrd 证明代理获取密钥，initrd 使用该密钥安装 TD 客户文件系统。

用户可以为存储使用其他加密方案，例如不使用 LUKS，而是使用其他加密存储格式。或者，他们还可以不使用本地存储，而依赖证明自己到网络服务器后从网络安装的卷。然而，目前本文件不包括对这种远程存储的支持。

注意: 常用的读/写 Linux 存储保护方法（包括 dmcrypt 和 dm 完整性）不提供回滚保护。
如果回滚攻击是一个问题，建议使用控制范围外的网络存储。缺乏回滚保护也会影响启用了内存交换的客户内核的客户私有内存回滚攻击。
由于此限制，我们建议禁用客户内存交换。


.. _sec-virtio:

VirtIO and shared memory
========================

The virtIO subsystem is controlled by the untrusted host/VMM. For the
application data transferred over the virtIO communication channel, its
confidentiality and integrity (and rollback when required) must be
guaranteed by the application-level mechanisms. For example, virtio block
IO can be encrypted and authenticated using dmcrypt or other similar mechanism,
virtio network communication can use TLS or similar for the transmitted data. 
Please also note that for host visible consoles, like virtio-console, there
is no existing method to protect the application data due to functional nature
of the console. For the production systems, we only recommend enabling network
console over ssh or similar. 

All the rest of virtio input received from the host/VMM must be considered
untrusted. We need to make sure the that the core virtio code and
enabled virtio drivers are hardened against the malicious inputs
received from host/VMM through exposed interfaces, such as pci config
space and shared memory.

The virtIO subsystem is also highly configurable with different options
possible for the virtual queue's types, transportation, etc. For the
virtual queues, currently the only mode that was hardened (by performing
code audit and fuzzing activities outlined in :ref:`tdx-guest-hardening`)
is a split virtqueue without indirect descriptor support, so this mode is the only
one recommended for the secure virtio communication. For the virtio
transportation, the Linux TDX guest kernel uses hardened virtio over PCI
transport and disables the virtio over MMIO. If virtio over MMIO support
is desired, it can be enabled given that the hardening of this mode is
performed. For the virtio over PCI, we also disable the
virtio-pci-legacy mode and only harden the virtio-pci-modern mode. For
some of above described virtio configurations (for example disabling the
virtio-pci-legacy mode), it is possible for the TDX guest userspace to
override the secure defaults (given enough privileges). But doing so
would open the unhardened code and is strongly discouraged.

VirtIO drivers are built around the virtio ring. The ring contains
descriptors, which are organized in a free list. The free list handling
has been recently hardened by moving out of the shared memory into
guest private memory. We assume the main attack point is the ring,
but we also harden the higher-level
enabled drivers such as virtio-block, virtio-net, virtio-console,
virtio-9p, and virtio-vsock. All other virtio drivers are disabled by
the TDX guest driver filter and are not hardened.

VirtIO accesses the pci config space by using virtio-specific pci config
space access functions that are part part of both code audit and fuzzing
activities. Most of the virtio shared memory accesses go through
virtio\_to\_cpu macros and their higher-level wrappers, which are also
used for auditing and injecting the fuzzing input. However, there still
can be other accesses to the shared memory that must be manually audited
and instrumented for fuzzing.


virtIO 子系统由不受信任的主机/VMM 控制。对于通过 virtIO 通信通道传输的应用程序数据，其机密性和完整性（以及需要时的回滚）必须通过应用程序级机制得到保证。例如，可以使用 dmcrypt 或其他类似机制对 virtio 块 IO 进行加密和身份验证，可以使用 TLS 或类似方法对通过 virtio 网络传输的数据进行加密。
请注意，对于主机可见的控制台（如 virtio-console），由于控制台的功能性质，目前没有现有方法保护应用程序数据。对于生产系统，我们只建议通过 ssh 或类似方式启用网络控制台。

从主机/VMM 接收的所有其他 virtio 输入都应视为不受信任。我们需要确保核心 virtio 代码和启用的 virtio 驱动程序针对通过暴露的接口（如 pci 配置空间和共享内存）从主机/VMM 接收的恶意输入进行了加固。

virtIO 子系统也是高度可配置的，可以为虚拟队列类型、传输等选择不同的选项。目前唯一经过加固的虚拟队列模式是没有间接描述符支持的拆分 virtqueue，因此这是推荐用于安全 virtio 通信的唯一模式。对于 virtio 传输，Linux TDX 客户内核使用加固的 virtio over PCI 传输并禁用 virtio over MMIO。如果需要启用 virtio over MMIO 支持，可以进行加固后启用。对于 virtio over PCI，我们还禁用了 virtio-pci-legacy 模式，只加固了 virtio-pci-modern 模式。对于上述描述的一些 virtio 配置（例如禁用 virtio-pci-legacy 模式），TDX 客户用户空间可以覆盖安全默认设置（在有足够权限的情况下）。但是这样做会打开未加固的代码，因此强烈不推荐。

VirtIO 驱动程序围绕 virtio 环构建。环包含描述符，这些描述符组织在一个空闲列表中。最近通过将空闲列表处理从共享内存中移出到客户私有内存中进行了加固。我们假设主要攻击点是环，但我们也加固了启用的高级驱动程序，如 virtio-block、virtio-net、virtio-console、virtio-9p 和 virtio-vsock。所有其他 virtio 驱动程序都被 TDX 客户设备过滤器禁用，未加固。

VirtIO 使用 virtio 特定的 pci 配置空间访问函数访问 pci 配置空间，这些函数是代码审计和模糊测试活动的一部分。大多数 virtio 共享内存访问通过 virtio_to_cpu 宏及其高级包装器进行，这些包装器也用于审计和注入模糊测试输入。然而，可能还有其他访问共享内存的情况，需要手动审计和对模糊测试进行调整。





.. _sec-spectre_v1:

Transient Execution attacks and their mitigation
================================================

Software running inside a TDX Guest, including TDX Guest Linux kernel
and enabled kernel drivers, needs to
be aware which potential transient execution attacks are applicable
and employ the
appropriate mitigations when needed. More information on this can be found
in `Trusted Domain Security Guidance for Developers <https://TBD>`_.

在 TDX 客户中运行的软件，包括 TDX 客户 Linux 内核和启用的内核驱动程序，需要了解哪些潜在的瞬时执行攻击适用并在需要时采取适当的缓解措施。有关更多信息，请参阅 Trusted Domain Security Guidance for Developers。


Bounds Check Bypass (Spectre V1)
------------------------------------------------

`Bounds Check Bypass
<https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/analyzing-bounds-check-bypass-vulnerabilities.html>`_
is a class of transient execution attack (also known as Spectre V1),
which typically requires an attacker who can control an offset used
during a speculative
read or write. For the classical attack surface between the
userspace and the OS kernel (ring 3 <-> ring 0), an adversary has
several ways to provide the necessary controlled inputs to the OS
kernel, i.e., via system call parameters, routines to copy data
between the userspace and the OS kernel, and others.

While a TDX guest VM is no different from a legacy guest VM in
terms of protecting this userspace <-> OS kernel boundary, an
adversary who controls the (untrusted)
host/VMM can provide inputs to a TDX guest kernel via a wider range of
interfaces. Examples of such interfaces include shared memory as well
as the `TDVMCALL-hypercall-based communication interfaces`_ described
above.
A Linux kernel running inside a TDX guest should take additional
measures to mitigate any potential Spectre v1 gadgets involving such
interfaces.

To facilitate the task of identifying potential Spectre v1 gadgets in the new
attack surface between an untrusted host/VMM <-> TDX guest Linux kernel, the `Smatch <http://smatch.sourceforge.net/>`_ static analyzer can be used.
It has an existing `check_spectre.c <https://repo.or.cz/smatch.git/blob/HEAD:/check_spectre.c>`_
pattern that has been recently enhanced to find potential Spectre v1 gadgets
on the data that can be influenced by an untrusted host/VMM using
`TDVMCALL-hypercall-based communication interfaces`_ interfaces, such as MSR,
CPUID, PortIO, MMIO and PCI config space read functions, as well as virtio-based
shared memory read functions.


边界检查绕过 是一类瞬时执行攻击（也称为 Spectre V1），通常需要攻击者能够控制在推测性读取或写入期间使用的偏移量。

对于传统的用户空间和操作系统内核之间的攻击面（ring 3 <-> ring 0），对手有多种方式可以向操作系统内核提供必要的受控输入，即通过系统调用参数、在用户空间和操作系统内核之间复制数据的例程等。

尽管 TDX 客户 VM 在保护此用户空间 <-> OS 内核边界方面与传统客户 VM 没有区别，但控制（不受信任的）主机/VMM 的对手可以通过更广泛的接口向 TDX 客户内核提供输入。这些接口的示例包括共享内存以及上面描述的 TDVMCALL-hypercall-based communication interfaces。

在 TDX 客户内运行的 Linux 内核应采取额外措施，以减轻涉及此类接口的任何潜在的 Spectre v1 漏洞的影响。

为帮助识别不受信任的主机/VMM <-> TDX 客户 Linux 内核的新攻击面中的潜在 Spectre v1 漏洞，可以使用 Smatch 静态分析器。它有一个现有的 check_spectre.c 模式，该模式最近得到了增强，以查找潜在的 Spectre v1 漏洞在不受信任的主机/VMM 使用 TDVMCALL-hypercall-based communication interfaces 接口（如 MSR、CPUID、PortIO、MMIO 和 PCI 配置空间读取功能以及基于 virtio 的共享内存读取功能）影响的数据上的潜在 Spectre v1 漏洞。


In order to configure the pattern to perform the Spectre v1 gadget
analysis on the host data, the following environmental variable must
be set prior to running the smatch analysis:

为了配置模式以对主机数据执行 Spectre v1 漏洞分析，在运行 smatch 分析之前必须设置以下环境变量：

   .. code-block:: bash

         export ANALYZE_HOST_DATA=""

To revert to the original behavior of the pattern, i.e.,
identification of Spectre v1 gadgets from userspace-induced inputs,
the same variable needs to be unset:

要恢复模式的原始行为，即从用户空间引发的输入中识别 Spectre v1 漏洞，必须取消设置相同的变量：

   .. code-block:: bash

         unset ANALYZE_HOST_DATA

For more information on how to setup smatch and use it to perform
analysis of the linux kernel please refer to `Smatch documentation <https://repo.or.cz/smatch.git/blob/HEAD:/Documentation/smatch.txt>`_ .

The output of the smatch check_spectre.c pattern is a list of
potential Spectre v1 gadgets applicable to the analyzed Linux kernel
source code. When the pattern is run for the whole kernel source tree
(using test_kernel.sh script and with ANALYZE_HOST_DATA variable set
as above), it will produce warnings in smatch_warns.txt file that
contains a list of potential Spectre v1 gadgets in the following
format:

有关如何设置 smatch 并使用它执行 Linux 内核分析的更多信息，请参阅 Smatch 文档。

smatch check_spectre.c 模式的输出是适用于分析的 Linux 内核源代码的潜在 Spectre v1 漏洞列表。当模式针对整个内核源代码树运行时（使用 test_kernel.sh 脚本并设置 ANALYZE_HOST_DATA 变量），它将在 smatch_warns.txt 文件中生成警告，其中包含潜在 Spectre v1 漏洞的列表，格式如下：

.. code-block:: bash

	arch/x86/kernel/tsc_msr.c:191 cpu_khz_from_msr() warn: potential
	spectre issue 'freq_desc->muldiv' [r]
	arch/x86/kernel/tsc_msr.c:206 cpu_khz_from_msr() warn: potential
	spectre issue 'freq_desc->freqs' [r]
	arch/x86/kernel/tsc_msr.c:207 cpu_khz_from_msr() warn: possible
	spectre second half.  'freq'
	arch/x86/kernel/tsc_msr.c:210 cpu_khz_from_msr() warn: possible
	spectre second half.  'freq'


Each reported item needs to be manually analyzed to determine if it is
a potential Spectre v1 gadget or a false positive. To minimize the
number of entries for manual analysis, the list in smatch_warns.txt
should be filtered against a list of drivers that are allowed for the
TDX guest kernel, since most of the potential reported Spectre v1
gadgets are going to be related to various x86 Linux kernel drivers.
The process_smatch_output.py script can be used for doing the
automatic filtering of the results, but its list of allowed drivers
needs to be adjusted to reflect the TDX guest kernel under analysis.
For the items that are determined to be potential Spectre v1 gadgets
during the manual analysis phase, the recommended mitigations listed
in `Analyzing Potential Bounds Check Bypass Vulnerabilities <https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/analyzing-bounds-check-bypass-vulnerabilities.html>`_ should be followed.

每个报告的项目需要手动分析，以确定它是否是潜在的 Spectre v1 漏洞或误报。为了最小化需要手动分析的条目数量，smatch_warns.txt 中的列表应根据允许 TDX 客户内核的驱动程序列表进行过滤，因为大多数潜在的报告 Spectre v1 漏洞都将与各种 x86 Linux 内核驱动程序有关。process_smatch_output.py 脚本可用于自动过滤结果，但其允许驱动程序列表需要调整以反映所分析的 TDX 客户内核。对于在手动分析阶段确定为潜在 Spectre v1 漏洞的项目，应遵循 Analyzing Potential Bounds Check Bypass Vulnerabilities 中列出的推荐缓解措施。

Summary
=======

The TDX guest kernel security architecture described in this document is
a first step towards building a secure Linux guest kernel for
confidential cloud computing (CCC). The security hardening techniques
described in this document are not specific to the Intel TDX technology,
but are applicable for any CCC technology that aims to help to remove the
host/VMM from TCB. While some of the hardening approaches outlined above
are still a work in progress or left for the future, it provides a solid
foundation for continuing this work by both the industry and the Linux
community.

本文档中描述的 TDX 客户端内核安全架构是为机密云计算 (CCC) 构建安全的 Linux 客户端内核的第一步。本文档中描述的安全硬化技术并不特定于 Intel TDX 技术，而适用于旨在帮助将主机/VMM 从 TCB 中移除的任何 CCC 技术。虽然上述概述的某些硬化方法仍在进行中或留待将来，但它为行业和 Linux 社区继续这项工作提供了坚实的基础。
