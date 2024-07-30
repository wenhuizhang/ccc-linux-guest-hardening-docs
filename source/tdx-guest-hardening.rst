.. _tdx-guest-hardening:

Intel® Trust Domain Extension Guest Linux Kernel Hardening Strategy
#####################################################################

Contributors:

Elena Reshetova, Tamas Lengyel, Sebastian Osterlund, Steffen Schulz， Wenhui Zhang


Purpose and Scope
=================

The main security goal of Intel® Trust Domain Extension (Intel® TDX)
technology is to remove the need for a guest VM to trust the host and
Virtual Machine Manager (VMM). However, it cannot by itself protect the
guest VM from host/VMM attacks that leverage existing paravirt-based
communication interfaces between the host/VMM and the guest, such as
MMIO, Port IO, etc. To achieve protection against such attacks, the guest
VM software stack needs to be hardened to securely handle an untrusted
and potentially malicious input from a host/VMM via the above-mentioned
interfaces. This hardening effort should be applied to a concrete set of
software components that are used within the guest software stack
(virtual BIOS, bootloader, Linux\* kernel and userspace), which is
specific to a concrete deployment scenario. To facilitate this process,
we have developed a hardening methodology and tools that are explained
below.

Intel® Trust Domain Extension（Intel® TDX）技术的主要安全目标是消除客户虚拟机（VM）对宿主机和虚拟机管理器（VMM）的信任需求。然而，它本身无法保护客户虚拟机免受利用宿主/VMM与客户之间现有基于半虚拟化的通信接口（如 MMIO、端口 I/O 等）的攻击。为了防御此类攻击，客户虚拟机软件栈需要加固，以安全地处理来自宿主/VMM的不可信且可能恶意的输入。这种加固工作应用于客户软件栈中的一组具体软件组件（虚拟 BIOS、引导加载程序、Linux* 内核和用户空间），这些组件特定于具体的部署场景。为了促进这一过程，我们开发了一种加固方法和工具，下面将进行说明。

The hardening approach presented in this document is by no means an
ultimate guarantee of 100% security against the above-mentioned attacks,
but merely a methodology built to our best knowledge and resource
limitations. In our environment, we have successfully applied it to the
Linux TDX MVP software stack (https://github.com/intel/tdx-tools)
to the trust domain (TD) guest Linux kernel and hardened many involved
kernel subsystems. This guide is written with the Linux kernel in mind,
but the outlined principles can be applied to any software component.

本文档中介绍的加固方法绝不是针对上述攻击提供100%安全保障的最终保证，而仅仅是根据我们所掌握的最佳知识和资源限制构建的一种方法论。在我们的环境中，我们已经成功地将其应用于Linux TDX MVP软件栈（https://github.com/intel/tdx-tools）到信任域（TD）客户Linux内核，并加固了许多涉及的内核子系统。本指南是以Linux内核为中心编写的，但概述的原则可应用于任何软件组件。

The overall threat model and security architecture for the TD guest
kernel is described in the :ref:`security-spec` and it is
recommended to be read together with this document.

TD（信任域）客户内核的整体威胁模型和安全架构在 :ref:security-spec 中进行了描述，建议与本文档一起阅读。

Hardening strategy overview
===========================

The overall hardening strategy shown in Figure 1 encompasses three
activities that are executed in parallel: attack surface minimization,
manual code audit, and code fuzzing. All of them are strongly linked and
the results from each activity are contributed as inputs to the other
activities. For example, the results of a manual code audit can be used
to decide whenever a certain feature should be disabled (attack surface
minimization) or should be a target for a detailed fuzzing campaign.
Similarly, the fuzzing results might affect the decision to disable a
certain functionality or indicate a place where a manual code audit is
required but have been missed by a static code analyzer.

图1所展示的整体加固策略涵盖了三项并行执行的活动：攻击面最小化、手动代码审计和代码模糊测试。这些活动之间联系紧密，每项活动的结果都会作为输入贡献给其他活动。例如，手动代码审计的结果可以用来决定是否应该禁用某个功能（攻击面最小化）或是否应该成为详细的模糊测试的目标。同样，模糊测试的结果可能影响禁用某个功能的决定，或指出需要手动代码审计的地方，但可能被静态代码分析器遗漏。


.. figure:: images/strategy.png
   :width: 5.51418in
   :height: 3.23958in

   Figure 1. Linux Guest kernel hardening strategy.




The following section provides a detailed description of each of these
activities. An overall crucial aspect to consider is the “definition of
done”, i.e., the criteria for when a hardening effort can be finished
and how the success of such effort is defined.

下一节将详细描述这些活动中的每一个。一个总体上至关重要的方面是考虑“完成的定义”，即确定何时可以结束加固工作以及如何定义这种努力的成功的标准。

The ideal “definition of done” criteria can be outlined as follows:

1. The guest kernel functionality and the VMM/host exposed interfaces
   are limited to the minimum required for its successful operation,
   given a chosen deployment scenario. This implies that only a minimal
   set of required drivers, kernel subsystems, and individual
   functionality is enabled.

2. All code paths that are enabled within the guest kernel and can take
   an untrusted input from VMM/host must be manually audited from the
   potential consequences of consuming the malformed data. Whenever a
   manual code audit identifies an issue that is a security concern, it
   must be addressed either by a bug fix or by disabling the involved
   code path, if possible.

3. All code paths that are enabled within the guest kernel and can take
   an untrusted input from VMM/host must be fuzzed using an appropriate
   fuzzing technique. The fuzzing technique must provide the coverage
   information to identify that a fuzzer has reached the required code
   paths and exercised them sufficiently. Whenever the fuzzing activity
   identifies an issue that is a security concern, it must be addressed
   either by a bug fix or by disabling the involved code path.


理想的“完成定义”标准可以概括如下：

1. 客户内核功能和 VMM/主机暴露的接口应限制为所选部署场景下成功操作所需的最低限度。这意味着只启用了必需的最小驱动程序集、内核子系统和个别功能。

2. 在客户内核中启用的所有代码路径，如果能从 VMM/主机接收不可信输入，则必须经过手动审核，以评估消费畸形数据的潜在后果。无论何时，如果手动代码审核识别出一个安全问题，必须通过修复错误或在可能的情况下禁用相关代码路径来解决。

3. 在客户内核中启用的所有代码路径，如果能从 VMM/主机接收不可信输入，则必须使用适当的模糊测试技术进行测试。模糊测试技术必须提供覆盖信息，以确认模糊测试工具已经到达所需的代码路径并充分执行它们。无论何时，如果模糊测试活动识别出一个安全问题，必须通过修复错误或在可能的情况下禁用相关代码路径来解决。

The success of the overall hardening effort is significantly more
difficult to measure. The total number of security concerns identified
by the manual code audit or fuzzing activity is a natural quantifier,
but it neither guarantees that the end goal of having a secure guest
kernel has been successfully reached nor does it necessarily indicate
that the chosen hardening approach is successful. The successful
operation of the guest kernel within the Linux TD software stack and the
absence of issues identified or reported during its deployment life cycle
is a much stronger, albeit a post-factum indicator.

整体加固努力的成功更难以衡量。通过手动代码审核或模糊测试活动识别出的安全问题总数是一个自然的量度指标，但它既不能保证已经成功达到拥有一个安全的客户内核的最终目标，也不一定表明选定的加固方法是成功的。客户内核在 Linux TD 软件堆栈中的成功运行以及在其部署生命周期期间未发现或报告的问题的缺失，是一个更为有力的，尽管是事后的指标。


Attack surface minimization
===========================

The main objective for this task is to disable as much code as possible
from the TD guest kernel to limit the number of interfaces exposed to
the malicious host/VMM. This is achieved by either explicitly disabling
certain unneeded features (for example early PCI code), by a generic
filtering approach, such as port IO filtering, driver filtering, etc or
by restricting access to the MMIO and PCI config space regions.

这项任务的主要目标是尽可能多地禁用 TD 客户内核中的代码，以限制暴露给恶意主机/VMM 的接口数量。这可以通过显式禁用某些不需要的功能（例如早期的 PCI 代码）、采用通用过滤方法（如端口 IO 过滤、驱动程序过滤等）或限制对 MMIO 和 PCI 配置空间区域的访问来实现。

Implemented filtering mechanisms
--------------------------------

All the implemented filtering mechanisms described below are runtime
mechanisms that limit TD guest functionality based on a set of default
allow lists defined in the kernel source code, but with a possibility to
override these defaults via a command line option mechanism. The latter
can be used for debugging purposes or for enabling a specific driver,
ACPI table, or KVM CPUID functionality that is required for a particular
deployment scenario.

下面描述的所有已实施的过滤机制都是运行时机制，它根据内核源代码中定义的一组默认允许列表限制 TD 客户功能，但可以通过命令行选项机制覆盖这些默认设置。后者可以用于调试目的或启用特定部署场景所需的特定驱动程序、ACPI 表或 KVM CPUID 功能。

.. list-table:: Filter status
   :widths: 10 30
   :header-rows: 1

   * - Filter name 过滤器名称
     - Purpose and current state 目的和当前状态
   * - Driver filter 驱动过滤器
     - Limits a set of drivers that are enabled in runtime for the TD guest kernel.
       By default, all PCI and ACPI bus drivers are blocked unless they are in the allow
       list. The current default allow list for the PCI bus is limited to the
       following virtio drivers: virtio\_net, virtio\_console, virtio\_blk, and
       9pnet\_virtio. 

       限制在运行时为 TD 客户内核启用的驱动程序集。默认情况下，除非驱动程序在允许列表中，否则所有 PCI 和 ACPI 总线驱动程序都被阻止。PCI 总线的当前默认允许列表仅限于以下 virtio 驱动程序：virtio_net、virtio_console、virtio_blk 和 9pnet_virtio。
   * - Port IO filter 端口 IO 过滤器
     - Limits a set of IO ports that can be used for communication between a TD
       guest kernel and the host/VMM. This feature is needed in addition to the
       above driver filtering mechanism, because should some drivers escape this
       mechanism, its port IO communication with the host/VMM will be limited to a
       small set of allowed ports. For example, some linux drivers might perform
       port IO reads in their initialization functions before doing the driver
       registration or some legacy drivers might not utilize the modern driver
       registration interface at all and therefore would be allowed by the above
       driver filter. In any case port IO filter makes sure that only a limited
       number of ports are allowed to be communicating with host/VMM. The port IO
       allow list can be found in :ref:`sec-io-ports`.
       Note that in the decompressed mode, the port IO
       filter is not active and therefore it is only applicable for early port IO
       and normal port IO.

       限制 TD 客户内核与主机/VMM 之间通信可以使用的 IO 端口集。除了上述驱动过滤机制之外，还需要此功能，因为如果某些驱动程序逃避了这种机制，其端口 IO 与主机/VMM 的通信将仅限于一小部分允许的端口。例如，某些 linux 驱动程序可能在进行驱动程序注册之前在其初始化函数中执行端口 IO 读取，或者某些旧驱动程序可能根本不使用现代驱动程序注册接口，因此会被上述驱动过滤器允许。无论如何，端口 IO 过滤器确保只有有限数量的端口被允许与主机/VMM 通信。端口 IO 允许列表可以在 :ref:sec-io-ports 中找到。注意，在解压模式下，端口 IO 过滤器不活跃，因此它仅适用于早期端口 IO 和常规端口 IO。
   * - ACPI table allow list ACPI 表允许列表
     - TDX virtual firmware (TDVF, for details see
       https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-virtual-firmware-design-guide-rev-1.pdf)
       measures a set of ACPI tables obtained from the host/VMM into TDX RTMR[
       0] measurement register. Thus, the set of tables passed by the host/VMM can
       be remotely attested and verified. However, it can be difficult for a
       remote verifier to understand the possible consequences from using a big
       set of various ACPI tables. Since most of the tables are not needed for a
       TDX guest, the implemented ACPI table allow list limits them to a small,
       predefined list with a possibility to pass additional tables via a command
       line option. The current allow list is limited to the following tables:
       XSDT, FACP, DSDT, FACS, APIC, and SVKL. Note that a presence of a minimal
       ACPI table configuration does not by itself guarantee the overall security
       hardening of ACPI subsystem in the TD guest kernel. The known limitations
       on ACPI hardening are described in :ref:`sec-acpi-tables`.
       
       TDX 虚拟固件（TDVF，详情见 https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-virtual-firmware-design-guide-rev-1.pdf） 将从主机/VMM 获得的一组 ACPI 表度量到 TDX RTMR[0] 测量寄存器中。因此，可以远程验证并核实主机/VMM 传递的表集。然而，远程验证者很难理解使用大量各种 ACPI 表可能带来的后果。由于大多数表对于 TDX 客户不是必需的，实施的 ACPI 表允许列表将它们限制为一个小的、预定义的列表，并且可以通过命令行选项传递额外的表。当前的允许列表限制为以下表：XSDT、FACP、DSDT、FACS、APIC 和 SVKL。注意，最小的 ACPI 表配置的存在本身并不保证 TD 客户内核中 ACPI 子系统的整体安全加固。ACPI 加固的已知限制在 :ref:sec-acpi-tables 中描述。
   * - KVM CPUID allow list and KVM hypercalls KVM CPUID 允许列表和 KVM 超调
     - KVM supports a set of hypercalls that a TD guest kernel can request a VMM to
       perform. On x86, this set is defined by a set of exposed CPUID bits. Some
       of the hypercalls can result in untrusted data being passed from a VMM
       KVM) to the guest kernel. To limit this attack vector, the implemented KVM
       CPUID allow list restricts the available KVM CPUID bits to a small
       predefined allow list. More information can be found in
       :ref:`sec-kvm-hypercalls` and :ref:`sec-kvm-cpuid`.
       
       KVM 支持一组超调，TD 客户内核可以请求 VMM 执行。在 x86 上，这一组由一组公开的 CPUID 位定义。一些超调可能导致不受信任的数据从 VMM (KVM) 传递给客户内核。为了限制这一攻击向量，实施的 KVM CPUID 允许列表限制了可用的 KVM CPUID 位到一个小的预定义允许列表。更多信息可以在 :ref:sec-kvm-hypercalls 和 :ref:sec-kvm-cpuid 中找到。



Explicitly disabled functionality
---------------------------------

Most of the functionality described below takes an untrusted host input
via MSR, port IO, MMIO, or pci config space reads through its codebase.
This has been identified using the static code analyzer described in the
next section. The decision to disable this functionality was made based
on the amount of code that would have to be manually audited, complexity
of the code involved, as well as the fact that this functionality is not
needed for the TD guest kernel.


大部分下面描述的功能通过其代码库通过 MSR、端口 IO、MMIO 或 PCI 配置空间读取接收不受信任的主机输入。这是使用下一节中描述的静态代码分析器识别的。基于需要手动审计的代码量、涉及的代码复杂性以及该功能对于 TD 客户内核不是必需的这一事实，做出了禁用这些功能的决定。

.. list-table:: Features
   :widths: 15 60
   :header-rows: 1

   * - Feature type
     - Description
   * - x86 features
     - Some x86 feature bits are explicitly cleared out by the TD guest kernel
       during an initialization, such as X86\_FEATURE\_MCE, X86\_FEATURE\_MTRR,
       X86\_FEATURE\_TME, X86\_FEATURE\_APERFMPERF, X86\_FEATURE\_CQM\_LLC.

       在初始化过程中，TD 客户内核明确清除了一些 x86 功能位，例如 X86\_FEATURE\_MCE, X86\_FEATURE\_MTRR,
       X86\_FEATURE\_TME, X86\_FEATURE\_APERFMPERF, X86\_FEATURE\_CQM\_LLC。
   * - Various PCI functionality
     - Some PCI related functionality that is not needed in the TD guest kernel is
       also explicitly disabled, such as early PCI, PCI quirks, and enhanced PCI
       parsing.

       一些在 TD 客户内核中不需要的 PCI 相关功能也被明确禁用，例如早期 PCI、PCI quirks（奇怪行为）和增强的 PCI 解析功能。
   * - Miscellaneous
     - A malicious host/VMM can fake PCI ids or some CPUID leaves to enable
       functionality that is normally disabled for a TDX guest and therefore not
       hardened. To help prevent this from happening, support for XEN, HyperV, and ACRN
       hypervisors, as well as AMD northbridge support, is explicitly disabled in
       the TD guest kernel.

       恶意的主机/VMM可以伪造 PCI ID 或一些 CPUID 指令码以启用通常为 TDX 客户禁用且因此未加固的功能。为了帮助防止这种情况发生，在 TD 客户内核中明确禁用了对 XEN、HyperV 和 ACRN 等虚拟机管理程序以及 AMD 北桥的支持。


Opt-in shared MMIO regions & PCI config space access
----------------------------------------------------

To further minimize the amount of code that needs to be hardened, we
require the TD guest kernel to explicitly opt-in any MMIO region that
needs to be shared with the host. This ensures that there is no
accidental shared MMIO regions created in the TD guest kernel that can
escape the hardening. A similar requirement applies to the PCI config
space accesses: only authorized devices are allowed to perform PCI
config space reads (this applies even to the PCI config space done from
the device initialization routine).

为了进一步减少需要加固的代码量，我们要求 TD 客户内核明确选择任何需要与主机共享的 MMIO 区域。这确保了不会在 TD 客户内核中意外创建可以逃避加固的共享 MMIO 区域。类似的要求也适用于 PCI 配置空间访问：只有授权设备才被允许执行 PCI 配置空间读取（这甚至适用于设备初始化过程中完成的 PCI 配置空间）。

.. _hardening-smatch-report:

Static Analyzer and Code Audit
==============================

Requirements and goals
----------------------

The attack surface minimization activity outlined in the previous
section helps to limit the amount of TD guest kernel code that actively
interacts with the untrusted host/VMM. It is not possible to fully
remove this interaction due to the functional requirements that the TD
guest has; it needs to be able to perform network communication, it
should be possible to interact with the TD guest via console, etc. Thus,
we need to be able to manually audit all the TD guest kernel enabled
code that consumes an untrusted input from the host/VMM to ensure it
does not use this input in an unsecure way.

上一节中概述的攻击面最小化活动有助于限制与不可信主机/VMM主动交互的 TD 客户内核代码的数量。由于 TD 客户的功能需求，无法完全消除这种交互；它需要能够进行网络通信，应该可以通过控制台与 TD 客户进行交互等。因此，我们需要能够手动审核所有使用来自主机/VMM的不可信输入的启用的 TD 客户内核代码，以确保它不以不安全的方式使用这些输入。

To perform a more focused manual code audit, the exact locations where
the untrusted host input is consumed by the TD guest kernel needs to be
identified automatically. We have defined the following requirements for
this process:

1. **Adjustability of custom kernel trees.** The method must be easy to
   use on any custom kernel tree with any set of applied patches and
   specified kernel configuration.

2. **Absence of code instrumentation.** The expected number of locations
   where the TD guest can take an untrusted input from the host goes
   well beyond 1500 places even after the functionality minimization
   step. This makes it impossible to manually instrument these
   locations, as well as keep maintaining the instrumentation through
   the kernel version changes, custom patch sets, etc.

3. **Open-source well established tool**. The tool should be easily
   accessible for open source and for the kernel community to use and
   should be actively maintained and supported.


为了执行更有针对性的手动代码审核，需要自动识别 TD 客户内核使用来自不可信主机的输入的确切位置。我们为此过程定义了以下要求：

1. 自定义内核树的可调整性。 该方法必须易于在任何自定义内核树上使用，无论应用了哪些补丁和指定的内核配置。

2. 无需代码插桩。 预期的 TD 客户可能从主机获取不可信输入的位置超过 1500 处，即使在功能最小化步骤之后。这使得手动插桩这些位置变得不可能，同时也难以通过内核版本更改、自定义补丁集等维护插桩。

3. 开源且成熟的工具。 该工具应该易于开源和内核社区使用，并且应该得到积极的维护和支持。



Check\_host\_input Smatch pattern
---------------------------------

Based on the above requirements, a Smatch static code analyzer
(http://smatch.sourceforge.net/) has
been chosen since it provides an easy interface to write custom patterns
to search for problematic locations in the kernel source tree. Smatch
already has a big set of existing patterns that have been used to find
many security issues with the current mainline kernel.

基于上述要求，选择了 Smatch 静态代码分析器（http://smatch.sourceforge.net/）因为它提供了一个简单的界面来编写自定义模式，以便在内核源代码树中搜索问题位置。Smatch 已经拥有一大套现有的模式，这些模式已经被用来发现当前主线内核的许多安全问题。

To identify the locations where a TD guest kernel can take an untrusted
input from the host/VMM, a custom Smatch pattern 
`check_host_input <https://repo.or.cz/smatch.git/blob/HEAD:/check_host_input.c>`_ 
has been written.
It operates based on a list of base “input functions” (contained
in `smatch_kernel_host_data <https://repo.or.cz/smatch.git/blob/HEAD:/smatch_kernel_host_data.c>`_),
i.e. low-level
functions that perform MSR, port IO, and MMIO
reads, such as native\_read\_msr, inb/w/l, readb/w/l, as well as
higher-level wrappers specific to certain subsystems. For example, PCI
config space uses many wrappers like pci\_read\_config,
pci\_bus/user\_read\_\* through its code paths to read the information
from the untrusted host/VMM. Whenever a function listed in 
`smatch_kernel_host_data <https://repo.or.cz/smatch.git/blob/HEAD:/smatch_kernel_host_data.c>`_
is detected in the code, the correct parameters (containing an input that
could have been supplied by the host) are marked as 'host_data' and
Smatch's taint analysis will perform propagation of this data through
the whole kernel codebase. The output of the check\_host\_input
pattern when run against the whole kernel tree is a list of all locations
in kernel where the 'host_data' is being processed, with exact code locations
and some additional information to assist the manual code audit process.


为了识别 TD 客户内核可以从主机/VMM 接受不信任输入的位置，编写了一个自定义 Smatch 模式 check_host_input <https://repo.or.cz/smatch.git/blob/HEAD:/check_host_input.c>_ 。它基于一个基本“输入函数”的列表运行（包含在 smatch_kernel_host_data <https://repo.or.cz/smatch.git/blob/HEAD:/smatch_kernel_host_data.c>_ 中），即执行 MSR、端口 IO 和 MMIO 读取的低级函数，如 native_read_msr、inb/w/l、readb/w/l，以及特定于某些子系统的更高级别的封装。例如，PCI 配置空间通过其代码路径使用许多封装，如 pci_read_config、pci_bus/user_read_* 从不信任的主机/VMM 读取信息。每当在代码中检测到 smatch_kernel_host_data <https://repo.or.cz/smatch.git/blob/HEAD:/smatch_kernel_host_data.c>_ 列出的函数时，将正确的参数（包含可能由主机提供的输入）标记为 'host_data'，并且 Smatch 的污点分析将执行这些数据在整个内核代码库中的传播。当在整个内核树上运行 check_host_input 模式时，输出是内核中处理 'host_data' 的所有位置的列表，包括确切的代码位置和一些额外信息以协助手动代码审计过程。


Additionally existing smatch patterns can take a benefit from the fact
that 'host_data' is now correctly tracked. For example, a modified
`check_spectre <https://repo.or.cz/smatch.git/blob/HEAD:/check_spectre.c>`_ 
Smatch pattern now is able to detect spectre v1 gadgets not only on the
userspace <->kernel surface, but also host <->guest surface. More
information can be found in `Transient Execution attacks and their mitigation <https://intel.github.io/ccc-linux-guest-hardening-docs/security-spec.html#transient-execution-attacks-and-their-mitigation>`_


此外，现有的 smatch 模式可以从现在正确追踪 'host_data' 的事实中获益。例如，修改后的 check_spectre <https://repo.or.cz/smatch.git/blob/HEAD:/check_spectre.c>_ Smatch 模式现在能够检测不仅在用户空间<->内核界面上的 spectre v1 gadgets，还能检测主机<->客户界面上的。更多信息可以在 瞬态执行攻击及其缓解 <https://intel.github.io/ccc-linux-guest-hardening-docs/security-spec.html#transient-execution-attacks-and-their-mitigation>_ 中找到。

The current approach using the check\_host\_input Smatch pattern has
several limitations. The main limitation is the importance of having a
correct list of input functions since the pattern will not detect the
invocations of functions not present in this list. Fortunately, the
low-level base functions for performing MSR, port IO, and MMIO read
operations are well-defined in the Linux kernel. Another limitation of
this approach is the inability to detect generic DMA-style memory accesses, since they
typically do not use any specific functions or wrappers to receive the
data from the host/VMM. An exception here is a virtIO ring subsystem
that uses virtio16/32/64\_to\_cpu wrappers in most of the places to
access memory locations residing in virtIO ring DMA pages. The
invocation of these wrappers can be detected by the check\_host\_input
Smatch pattern and the findings can be reported similarly as for other
non-DMA accesses.

使用 check_host_input Smatch 模式的当前方法有几个局限性。主要限制是有一个正确的输入函数列表的重要性，因为模式将无法检测未在此列表中出现的函数调用。幸运的是，执行 MSR、端口 IO 和 MMIO 读取操作的低级基础函数在 Linux 内核中定义得很好。这种方法的另一个限制是无法检测通用 DMA 风格的内存访问，因为它们通常不使用任何特定的函数或封装来从主机/VMM 接收数据。这里的一个例外是 virtIO 环子系统，在大多数位置使用 virtio16/32/64_to_cpu 封装来访问位于 virtIO 环 DMA 页面的内存位置。这些封装的调用可以被 check_host_input Smatch 模式检测到，并且发现可以类似于其他非 DMA 访问一样被报告。

.. code-block:: shell

   arch/x86/pci/irq.c:1201 pirq_enable_irq() warn:
   {9123410094849481700}read from the host using function
   'pci_read_config_byte' to an int type local variable 'pin', type is
   uchar;

   arch/x86/pci/irq.c:1216 pirq_enable_irq() error:
   {11769853683657473858}Propagating an expression containing a tainted
   value from the host 'pin - 1' into a function
   'IO_APIC_get_PCI_irq_vector';

   arch/x86/pci/irq.c:1228 pirq_enable_irq() error:
   {15187152360757797804}Propagating a tainted value from the host 'pin'
   into a function 'pci_swizzle_interrupt_pin';

   arch/x86/pci/irq.c:1229 pirq_enable_irq() error:
   {8593519367775469163}Propagating an expression containing a tainted
   value from the host 'pin - 1' into a function
   'IO_APIC_get_PCI_irq_vector';

   arch/x86/pci/irq.c:1233 pirq_enable_irq() warn:
   {3245640912980979571}Propagating an expression containing a tainted
   value from the host '65 + pin - 1' into a function '_dev_warn';

   arch/x86/pci/irq.c:1243 pirq_enable_irq() warn:
   {11844818720957432302}Propagating an expression containing a tainted
   value from the host '65 + pin - 1' into a function '_dev_info';

   arch/x86/pci/irq.c:1262 pirq_enable_irq() warn:
   {14811741117821484023}Propagating an expression containing a tainted
   value from the host '65 + pin - 1' into a function '_dev_warn';

Figure 2. Sample output from the check\_host\_input Smatch pattern.

The sample output of the check\_host\_input Smatch pattern is shown on
Figure 2. The function pirq\_enable\_irq performs a PCI config space
read operation using a pci\_read\_config\_byte input function (PCI
config space specific higher-level wrapper) and stores the result in the
local variable pin (type uchar). Next, this local variable is being
supplied as an argument to the IO\_APIC\_get\_PCI\_irq\_vector and
pci\_swizzle\_interrupt\_pin functions, as well as to several
\_dev\_info/warn functions. The relevant code snippet with highlighted
markings is shown in Figure 3.

check_host_input Smatch 模式的示例输出显示在图 2 中。函数 pirq_enable_irq 使用 pci_read_config_byte 输入函数（PCI 配置空间特定的高级封装）执行 PCI 配置空间读操作，并将结果存储在局部变量 pin（类型为 uchar）中。接下来，这个局部变量被作为参数提供给 IO_APIC_get_PCI_irq_vector 和 pci_swizzle_interrupt_pin 函数，以及几个 _dev_info/warn 函数。相关代码片段及其高亮标记显示在图 3 中。

.. figure:: images/code-snipped-pirq.png
   :width: 6.14865in
   :height: 5.68750in

Figure 3. Code snippet for the pirq\_enable\_irq function.

.. _hardening-performing-manual-audit:

Performing a manual code audit
------------------------------

The check\_host\_input Smatch pattern can be run as any other existing
smatch patterns following instructions in `Smatch documentation <https://repo.or.cz/smatch.git/blob/HEAD:/Documentation/smatch.txt>`_ .
One important precondition before running the pattern is to build the smatch cross
function database first (at least 5-6 times) in order to make sure that
the database contains the propagated taint data. The database pre-build step needs
to happen only once per kernel tree and is not needed in the subsequent
analysis runs. Also, since the pattern is automatically disabled in the smatch
default configuration (due to a significant volume output), it must be explicitly 
enabled in the `smatch header file <https://repo.or.cz/smatch.git/blob/HEAD:/check_list.h#l232>`_ 
before performing an audit run.

check_host_input Smatch 模式可以按照《Smatch 文档》（https://repo.or.cz/smatch.git/blob/HEAD:/Documentation/smatch.txt）中的说明运行，就像运行任何其他现有的 smatch 模式一样。在运行该模式之前，一个重要的前提条件是首先构建 smatch 跨函数数据库（至少 5-6 次），以确保数据库包含传播的污点数据。数据库预构建步骤只需在每个内核树上进行一次，并且在后续分析运行中不需要。此外，由于模式在 smatch 默认配置中被自动禁用（因为输出量较大），在进行审计运行之前，必须在 smatch 头文件（https://repo.or.cz/smatch.git/blob/HEAD:/check_list.h#l232）中显式启用该模式。

The `ccc-linux-guest-hardening repository <https://github.com/intel/ccc-linux-guest-hardening/blob/master/docs/generate_smatch_audit_list.md>`_ 
contains instructions on how to obtain the output of check\_host\_input smatch pattern
using automated scripts provided with the repository.
Internally, when a manual code audit activity is performed, the list of overall
findings is filtered using the process\_smatch\_output.py python
script to discard the results for the areas that are disabled within the
TD guest kernel. For example, most of the drivers/\* and sound/\*
results are filtered out except for the drivers that are enabled in the
TD guest kernel. Additionally, process\_smatch\_output.py also discards
findings from other enabled by default smatch patterns. 

ccc-linux-guest-hardening 仓库（https://github.com/intel/ccc-linux-guest-hardening/blob/master/docs/generate_smatch_audit_list.md）包含了使用该仓库提供的自动化脚本获取 check_host_input smatch 模式输出的指南。在执行手动代码审计活动时，使用 process_smatch_output.py Python 脚本过滤整体发现列表，以舍弃在 TD 客户内核中被禁用的区域的结果。例如，大多数 drivers/* 和 sound/* 的结果被过滤掉，除了在 TD 客户内核中启用的驱动程序。此外，process_smatch_output.py 还会丢弃其他默认启用的 smatch 模式的发现。



After following instructions in `ccc-linux-guest-hardening repository <https://github.com/intel/ccc-linux-guest-hardening/blob/master/docs/generate_smatch_audit_list.md>`_ the reduced list of smatch
pattern findings, smatch\_warns.txt, can be analyzed
manually by looking at each reported code location and verifying that
the consumed or propagated host input is used in a secure way.

遵循 ccc-linux-guest-hardening 仓库 中的指南后，可以手动分析减少后的 smatch 模式发现列表 smatch_warns.txt，通过查看每个报告的代码位置并验证消费或传播的主机输入是否以安全的方式使用。

Each finding is therefore manually classified into one of the following
statuses:

.. list-table:: Findings
   :widths: 15 60
   :header-rows: 1


   * - **Status**
     - **Meaning**
   * - excluded
     - This code location is not reachable inside a TD guest due to it being
       non-Intel code or functionality that is disabled for the TD guest kernel.
       The reason these lines are not filtered from the Smatch report by the above
       process\_smatch\_output.py python script is additional checks that we do
       when executing the fuzzing activity described in the next section. We
       perform an additional verification that none of these excluded code
       locations can be reached by the fuzzer.

       由于非英特尔代码或已为 TD 客户内核禁用的功能，这个代码位置在 TD 客户中无法访问。这些行之所以没有被上述 process_smatch_output.py Python 脚本从 Smatch 报告中过滤掉，是因为我们在下一节描述的模糊测试活动中执行了额外的检查。我们进行额外的验证，以确保没有任何这些被排除的代码位置可以被模糊器访问。
   * - unclassified
     - This code location is reachable inside TDX guest (i.e. not excluded), but
       has not been manually audited yet. 

       该代码位置在 TDX 客户中可达（即未被排除），但尚未进行手动审计。
   * - wrapper
     - The function that consumes or propagates a host input is a higher-level wrapper. The
       function is being checked for processing the host input in a secure way,
       but additionally all its callers are also reported by the Smatch pattern
       and the code audit happens on each caller.

       消费或传播主机输入的函数是一个高级包装器。该函数被检查以确保以安全的方式处理主机输入，但此外，其所有调用者也由 Smatch 模式报告，每个调用者都进行代码审计。
   * - trusted
     - The consumed input comes from a trusted source for Intel TDX guest, i.e.
       it is provided by the TDX module or context-switched for every TDX guest
       (i.e. native). This is applicable for both MSRs and CPUIDs. More information
       can be found in :ref:`sec-msrs` and :ref:`sec-cpuids`.

	消费的输入来自于 Intel TDX 客户的可信来源，即由 TDX 模块提供或为每个 TDX 客户进行上下文切换（即原生）。这适用于 MSR 和 CPUID。更多信息可以在 :ref:sec-msrs 和 :ref:sec-cpuids 中找到。

   * - safe
     - The consumed or propagated host input looks to be used in a secure way

	消费或传播的主机输入看起来是以安全的方式使用的。
   * - concern
     - The consumed or propagated host input is used in an unsecure way. There is an additional
       comment indicating the exact reason. All concern items must be addressed
       either by disabling the code that performs the host input processing or by
       writing a patch that fixes the problematic input processing.

       消费或传播的主机输入以不安全的方式使用。还有一个额外的评论指出了确切的原因。所有关注项必须通过禁用执行主机输入处理的代码或通过编写修复问题输入处理的补丁来解决。

The main challenge in this process is a decision whenever a certain
reported code location is considered “safe” or “concern”. The typical
list of “concern” items can be classified into two categories:

1. **Memory access issues**. A host input is being used as an address,
   pointer, buffer index, loop iterator bound or anything else that
   might result in the host/VMM being able to have at least partial
   control over the memory access that a TD guest kernel performs.

2. **Conceptual security issues.** A host input is being used to affect
   the overall security of the TD guest or its features. An example is
   when an untrusted host input is used for operating TD guest clock or
   affecting KASLR randomization.

这个过程中的主要挑战是决定何时将某个报告的代码位置视为‘安全’或‘关注’。‘关注’项的典型列表可以分为两类：

1. 内存访问问题。主机输入被用作地址、指针、缓冲区索引、循环迭代器界限或任何其他可能导致主机/VMM至少能够部分控制 TD 客户内核执行的内存访问的内容。

2. 概念性安全问题。主机输入被用来影响 TD 客户的整体安全或其功能。一个例子是使用不受信任的主机输入来操作 TD 客户的时钟或影响 KASLR 随机化。


Applying code audit results to different kernel trees
-----------------------------------------------------

The provided `sample audit output <https://github.com/intel/ccc-linux-guest-hardening/blob/master/bkc/audit/sample_output/6.0-rc2/smatch_warns_6.0_tdx_allyesconfig_filtered_analyzed>`_ 
of check\_host\_input smatch pattern findings for the version 6.0-rc2 kernel
contains results of our manual code audit activity for this kernel version
(Please note that the above provided list
does not have 'safe' or 'concern' markings published) and
can be used as a baseline for performing a manual audit on other kernel
versions or on custom vendor kernels. The suggested procedure to analyse
a custom kernel is documented in 'Targeting your own guest kernel'[TBD].

The automatic transfer of the code audit labels (trusted, excluded,
wrapper, etc.) from the baseline kernel audit version is  based on the
unique identifiers for each finding. Examples of these findings are
shown in orange in Figure 2. Identifiers from a baseline kernel tree
finding and target tree finding must match for a finding to be
automatically transferred. An identifier is a simple djb2 hash of
an analyzed code expression together with a relative offset from the
beginning of the function where this expression is located. It is
possible to further improve the calculation of identifiers (and
therefore improve the accuracy of automatic result transfer) to include
the code around the expression in a way that it is done in various
version control systems, but it has not been done yet.

所提供的 示例审计输出 <https://github.com/intel/ccc-linux-guest-hardening/blob/master/bkc/audit/sample_output/6.0-rc2/smatch_warns_6.0_tdx_allyesconfig_filtered_analyzed>_ 包含了版本 6.0-rc2 内核的 check_host_input smatch 模式查找结果，这些结果来自我们对此内核版本的手动代码审计活动（请注意，上述列表未公布‘安全’或‘关注’标记），可作为在其他内核版本或自定义供应商内核上执行手动审计的基线。分析自定义内核的建议程序记录在 'Targeting your own guest kernel'[待定] 中。

从基线内核审计版本到代码审计标签（信任、排除、包装器等）的自动转移是基于每个发现的唯一标识符。这些发现的示例在图 2 中以橙色显示。基线内核树的发现和目标树的发现的标识符必须匹配，才能自动转移发现。一个标识符是一个简单的 djb2 散列，它与分析的代码表达式一起使用，以及此表达式所在的函数开始的相对偏移量。有可能进一步改进标识符的计算（从而提高自动结果转移的准确性），包括在各种版本控制系统中所做的那样，将表达式周围的代码包括进来，但目前还未实现。

TD Guest Fuzzing
================

Fuzzing is a well-established software validation technique that can be
used to find problems in input handling of various software components.
In our TD guest kernel hardening project, we used it to validate and
cross check the results from the manual code audit activity.

The main goals for the fuzzing activity are:

1. Automatically exercise the robustness of the existing TD guest kernel
   code that was identified by the Smatch pattern as handling the input
   from the host/VMM.

2. Identify new TD guest kernel code locations that handle the input
   from the host/VMM and were missed by the Smatch pattern (for example
   some virtIO DMA accesses). When such locations are identified, the
   Smatch pattern can be further improved to catch these and similar
   places in other parts of the kernel code.

3. Automatically verify that the code that is expected to be disabled in
   the TD guest kernel (and thus not manually audited at all) is indeed
   not executed/not reachable in practice.

The primary ways of consuming untrusted host/VMM is by using either TDVMCALLs or
DMA shared memory as used for example by the VirtIO layer. Additionally, the
code paths that consume untrusted input may invoked automatically during boot,
or require some additional stimulus to execute during runtime.

In the following we review options we considered for generating potential
relevant userspace activity and fuzzing the various relevant input interfaces
during boot as well as during runtime.


模糊测试是一种成熟的软件验证技术，可用于发现各种软件组件的输入处理中的问题。在我们的 TD 客户内核加固项目中，我们使用它来验证和交叉检查手动代码审计活动的结果。

模糊测试活动的主要目标包括：

1. 自动测试通过 Smatch 模式识别的处理来自主机/VMM输入的现有 TD 客户内核代码的鲁棒性。

2. 识别处理来自主机/VMM的输入但未被 Smatch 模式捕获的新的 TD 客户内核代码位置（例如某些 virtIO DMA 访问）。当这些位置被识别出来时，可以进一步改进 Smatch 模式，以捕获内核代码的其他部分中的这些和类似的位置。

3. 自动验证预期在 TD 客户内核中被禁用（因此根本没有手动审计）的代码实际上未被执行/不可达。

消费不受信任的主机/VMM的主要方式是使用 TDVMCALL 或 DMA 共享内存，例如由 VirtIO 层使用。此外，消费不受信任输入的代码路径可能会在启动时自动调用，或者需要在运行时执行某些额外的刺激才能执行。

接下来，我们将回顾我们考虑的用于生成潜在相关用户空间活动并在启动以及运行时对各种相关输入接口进行模糊测试的选项。

TDX emulation setup
===================

Running a fully functional TDX guest requires CPU and HW support that is only
available on future Intel Xeon platforms. On contrary, our TDX
emulation setup allows testing SW running inside TDX guest VM early on ahead of
HW availability. It can be run on any recent and commonly available Intel
platforms without any special HW features. However, it is important to note that
this emulation setup is very limited in the amount of features it supports
and is not secure: emulated TDX guest runs under full control of the host
and VMM.

The main challenge for the setup is the emulation of the Intel TDX module.
Intel TDX module is a special SW module that plays a role of a secure shim between
the TDX host and TDX guest and provides an extensive API towards both VMM and TDX guest.
However, since our goal is only fuzzing of the TDX guest kernel,
we need a minimal emulation of the TDX Seam module that can support the basic set
of calls that TDX guest does towards the TDX module,
as well as wrapping such calls into existing kvm interfaces.
For more details about the actual Intel TDX module and its functionality please see
`Intel TDX module architecture specification <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>`_


运行一个完全功能的 TDX 客户需要 CPU 和硬件支持，这些支持只在未来的英特尔至强平台上可用。相反，我们的 TDX 模拟设置允许在硬件可用之前提前测试在 TDX 客户虚拟机内运行的软件。它可以在任何最近和常见的英特尔平台上运行，无需任何特殊硬件功能。然而，重要的是要注意，这种模拟设置在它支持的功能数量上非常有限，并且不是安全的：模拟的 TDX 客户在主机和 VMM 的完全控制下运行。

设置的主要挑战是模拟英特尔 TDX 模块。英特尔 TDX 模块是一个特殊的软件模块，充当 TDX 主机和 TDX 客户之间的安全中间件，并向 VMM 和 TDX 客户提供广泛的 API。然而，由于我们的目标仅是对 TDX 客户内核进行模糊测试，我们需要对 TDX Seam 模块进行最小化模拟，以支持 TDX 客户对 TDX 模块进行的基本调用集，以及将此类调用包装到现有的 KVM 接口中。有关实际英特尔 TDX 模块及其功能的更多详细信息，请参见英特尔 TDX 模块架构规范 <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>`_ 。



Implementation details
----------------------
The TDX emulation setup is implemented as a simple Linux kernel module with the
code in arch/x86/kvm/vmx/seam.c. Whenever the core TDX code in KVM performs
basic lifecycle operations on the TDX guest (initialization, startup, destruction,
etc.) it would call the respected functions in the TDX emulation setup (seam_tdcreatevp,
seam_tdinitvp/tdfreevp, seam_tdenter, etc.) instead of the actual TDX functions.
The emulated seam module supports a minimal set of exit reasons from the TDX guest
(including EXIT_REASON_TDCALL, EXIT_REASON_CPUID, EXIT_REASON_EPT_VIOLATION) and
inserts a #VE exception into an emulated TDX guest when the guest performs
operations on MSRs, CPUIDs, portIO and MMIO, as well as on guest's EPT violations.
Emulation performed by the TDX emulation setup is currently not exact but mainly focused
on exercising and testing the relevant TDX support by the guest OS.
Please refer to section 24 of 
`Intel TDX module architecture specification <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>`_ for official guidance on TDX module interfaces. 
For example, for the emulation of the MSRs and CPUIDs virtualization the emulated seam
module does not adhere to the TDX module specification on MSR and CPUID accesses
outlined in section 19 of 
`Intel TDX module architecture specification <https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf>`_ Instead it just inserts a #VE event on most of the MSRs
operations and for the CPUID leaves greater than 0x1f or outside of 0x80000000u-0x80000008u
range. The code in arch/x86/kvm/vmx/seam.c: seam_inject_ve() function can be checked
for up-to-date details. 


TDX 模拟设置是作为一个简单的 Linux 内核模块实现的，代码位于 arch/x86/kvm/vmx/seam.c。每当 KVM 中的核心 TDX 代码对 TDX 客户执行基本生命周期操作（初始化、启动、销毁等）时，它会调用 TDX 模拟设置中的相应函数（seam_tdcreatevp、seam_tdinitvp/tdfreevp、seam_tdenter 等），而不是实际的 TDX 函数。模拟的 seam 模块支持来自 TDX 客户的最小退出原因集（包括 EXIT_REASON_TDCALL、EXIT_REASON_CPUID、EXIT_REASON_EPT_VIOLATION），并在客户执行 MSR、CPUID、portIO 和 MMIO 操作以及客户的 EPT 违规时向模拟的 TDX 客户插入 #VE 异常。TDX 模拟设置的模拟目前不是精确的，主要集中在练习和测试客户操作系统的相关 TDX 支持上。请参阅英特尔 TDX 模块架构规范第 24 节，以获取有关 TDX 模块接口的官方指导。例如，对于 MSRs 和 CPUIDs 虚拟化的模拟，模拟的 seam 模块不遵循第 19 节中概述的 TDX 模块规范关于 MSR 和 CPUID 访问的规定。相反，它在大多数 MSR 操作上插入 #VE 事件，并且对于大于 0x1f 的 CPUID 叶子或超出 0x80000000u-0x80000008u 范围的操作同样处理。有关最新细节，请检查 arch/x86/kvm/vmx/seam.c 中的 seam_inject_ve() 函数的代码。


Fuzzing Kernel Boot
===================

The majority of input points identified by Smatch analysis and manual audit are
invoked as part of kernel boot.
The invocation of these code paths is usually hard to achieve at runtime
after the kernel has already booted due to absence of re-initialization
paths for many of these kernel subsystems.

We have adopted the `kAFL Fuzzer
<https://github.com/IntelLabs/kAFL>`__ for effective feedback fuzzing of the Linux
bootstrapping phase. Using a combination of fast VM snapshots and kernel
hooks, kAFL allows flexible harnessing of the relevant kernel
sub-systems, fast recovery from benign error conditions, and automated
reporting of any desired errors and exceptions handlers.


通过 Smatch 分析和手动审计识别的大多数输入点是作为内核启动的一部分被调用的。这些代码路径的调用通常很难在内核已经启动后的运行时实现，因为许多这些内核子系统没有重新初始化的路径。

我们采用了 kAFL Fuzzer <https://github.com/IntelLabs/kAFL>__ 来有效地反馈 Linux 启动阶段的模糊测试。通过结合快速 VM 快照和内核钩子，kAFL 允许灵活地利用相关的内核子系统，快速从良性错误条件中恢复，并自动报告任何所需的错误和异常处理。

.. figure:: images/kAFL-overview.png
   :width: 3.48364in
   :height: 3.73366in

   Figure 4. kAFL overview. 1) start of fuzzing (entry to kernel) 2)
   fuzzing harness 3) input fuzz buffer from host 4) MSR/PIO/MMIO causes a
   #VE 5) the agent injects a value obtained from 6) the input buffer 7)
   finally, reporting back the status to the host (crash/hang/ok)
   

Agent
-------

While kAFL can work based on binary rewrite and traps, the more
flexible approach is to modify the target’s source code. This
implements an agent that directly hooks relevant subsystems and
low-level input functions and feeds fuzzing input. At a high level,
our agent implementation consists of three parts:

a. **Core agent logic**: This includes fuzzer initialization and helper
   functions for logging and debug. The fuzzer is initialized with
   tdg\_fuzz\_enable(), and accepts control input via tdg\_fuzz\_event()
   to start/stop/pause input injection or report an error event.
   https://github.com/IntelLabs/kafl.linux/blob/kafl/fuzz-5.15-3/arch/x86/kernel/kafl-agent.c

b. **Input hooks**: We leverage the tdx\_fuzz hooks of in the
   guest kernel as defined by `Simple Fuzzer Hooks`_ as well as
   virtio16/32/64\_to\_cpu wrappers for VirtIO DMA input.
   When enabled, the fuzzing hooks are implemented to sequentially
   consume input from a payload buffer maintained by the agent. Fuzzing
   stops when the buffer is fully consumed or other exit conditions are
   met.
   https://github.com/IntelLabs/kafl.linux/commit/1e5206fbd6a3050c4b812a826de29982be7a5905

c. **Exit and reporting hooks**: We added tdx\_fuzz\_event() calls to
   common error handlers such as panic() and kasan\_report(), but also
   halt\_loop() macros etc. Moreover, the printk subsystem has been
   modified to log buffers directly via hypercalls. This allows report
   error conditions to be returned to the fuzzer and to collect any
   diagnostics before immediately restoring the initial snapshot for
   next execution.


虽然 kAFL 可以基于二进制重写和陷阱工作，但更灵活的方法是修改目标的源代码。这实现了一个直接挂钩相关子系统和低级输入函数并提供模糊输入的代理。从高层次来看，我们的代理实现包括三个部分：

a. 核心代理逻辑：这包括模糊器的初始化和用于日志记录和调试的辅助函数。模糊器通过 tdg_fuzz_enable() 初始化，并接受通过 tdg_fuzz_event() 的控制输入来开始/停止/暂停输入注入或报告错误事件。 https://github.com/IntelLabs/kafl.linux/blob/kafl/fuzz-5.15-3/arch/x86/kernel/kafl-agent.c

b. 输入钩子：我们利用客户内核中定义的 Simple Fuzzer Hooks_ 以及用于 VirtIO DMA 输入的 virtio16/32/64_to_cpu 包装器中的 tdx_fuzz 钩子。
启用后，模糊钩子被实现为从代理维护的有效负载缓冲区中顺序消费输入。当缓冲区完全消耗或满足其他退出条件时，模糊测试停止。https://github.com/IntelLabs/kafl.linux/commit/1e5206fbd6a3050c4b812a826de29982be7a5905

c. 退出和报告钩子：我们在常见的错误处理程序如 panic() 和 kasan_report()，但也包括 halt_loop() 宏等中添加了 tdx_fuzz_event() 调用。此外，printk 子系统已经被修改为通过超调用直接记录缓冲区。这允许将错误条件报告给模糊器，并在立即恢复初始快照以进行下一次执行前收集任何诊断信息。


Harnesses Definition
--------------------

Our kAFL agent implements a number of harnesses covering key phases of boot:

-  Early boot process: EARLYBOOT, POST\_TRAP, and START\_KERNEL

-  Subsystem initialization: REST\_INIT, DO\_BASIC, DOINITCALLS,
   DOINITCALLS\_PCI, DOINITCALLS\_VIRTIO, DOINITCALLS\_ACPI, and
   DOINITCALLS\_LEVEL\_X

-  Full boot (ends just before dropping to userspace): FULL\_BOOT

-  Kretprobe-based single function harnesses: VIRTIO\_CONSOLE\_INIT and
   EARLY\_PCI\_SERIAL\_INIT

The full list of boot harnesses with descriptions is available at
https://github.com/intel/ccc-linux-guest-hardening/blob/master/docs/boot_harnesses.txt

These harnesses are enabled in the guest Linux kernel by setting up the
kernel build configuration parameters in such a way that the desired
harness is enabled. For example, set
CONFIG\_TDX\_FUZZ\_HARNESS\_EARLYBOOT=y to enable the EARLYBOOT harness.
When enabled, the kernel will execute a tdx\_fuzz\_enable() call at the
beginning of the harness and a corresponding end call at the end of the
harness. These calls cause kAFL to take a snapshot at the first fuzzing
input consumed in the harness, and to reset the snapshot once the
execution reaches the end of the harness. The fuzzer will continue
resetting the snapshot in a loop -- having it consume different fuzzing
input on each reset -- until the fuzzing campaign is terminated.

During the campaign, the fuzzer automatically logs error cases, such as
crashes, sanitizer violations, or timeouts. Detailed (binary edge)
traces and kernel logs can be extracted in post-processing runs
(coverage gathering). To understand the effectiveness of a campaign, we
map achieved code coverage to relevant input code paths identified by
:ref:`hardening-smatch-report` ("Smatch matching").

虽然 kAFL 可以基于二进制重写和陷阱工作，但更灵活的方法是修改目标的源代码。这实现了一个直接挂钩相关子系统和低级输入函数并提供模糊输入的代理。从高层次来看，我们的代理实现包括三个部分：

a. 核心代理逻辑：这包括模糊器的初始化和用于日志记录和调试的辅助函数。模糊器通过 tdg_fuzz_enable() 初始化，并接受通过 tdg_fuzz_event() 的控制输入来开始/停止/暂停输入注入或报告错误事件。
https://github.com/IntelLabs/kafl.linux/blob/kafl/fuzz-5.15-3/arch/x86/kernel/kafl-agent.c

b. 输入钩子：我们利用客户内核中定义的 Simple Fuzzer Hooks_ 以及用于 VirtIO DMA 输入的 virtio16/32/64_to_cpu 包装器中的 tdx_fuzz 钩子。
启用后，模糊钩子被实现为从代理维护的有效负载缓冲区中顺序消费输入。当缓冲区完全消耗或满足其他退出条件时，模糊测试停止。
https://github.com/IntelLabs/kafl.linux/commit/1e5206fbd6a3050c4b812a826de29982be7a5905

c. 退出和报告钩子：我们在常见的错误处理程序如 panic() 和 kasan_report()，但也包括 halt_loop() 宏等中添加了 tdx_fuzz_event() 调用。此外，printk 子系统已经被修改为通过超调用直接记录缓冲区。这允许将错误条件报告给模糊器，并在立即恢复初始快照以进行下一次执行前收集任何诊断信息。


Example Workflow
--------------------

Running a boot time fuzzing campaign using our kAFL-based setup
typically consists of three stages, namely:

#. **Run fuzzing campaign(s).** Here we run the fuzzing campaign itself.
   The duration of the campaign typically depends on which harness is
   being used, how much parallelism can be used, etc. We have included a
   script (fuzz.sh) that sets up a campaign with some default settings.
   Make sure the guest kernel with the kAFL agent is checked out in
   ~/tdx/linux-guest. Select a harness that you want to use for fuzzing
   (in the next examples we will use the DOINITCALLS\_LEVEL\_4 harness).
   Using our fuzz.sh script, you can run a campaign in the following
   manner:

   .. code-block:: bash

      ./fuzz.sh full ./linux-guest/

   This starts a single fuzzing campaign, with the settings specified
   in fuzz.sh. You can get a more detailed view of the status of the
   campaign using the kafl\_gui.py tool:

   .. code-block:: bash

      kafl_gui.py /dev/shm/$USER_tdfl

#. **Gather the line coverage.** Once the campaign has run for long
   enough, we can extract the code line coverage from the campaign’s
   produced fuzzing corpus.

   .. code-block:: bash

      ./fuzz.sh cov /dev/shm/$USER\_tdfl

   This produces output files in the /dev/shm/$USER\_tdfl/traces
   directory, containing information, such as the line coverage (for
   example, see the file traces/addr2line.lst).

#. **Match coverage against Smatch report.** Finally, to get an idea of
   what the campaign has covered, we provide some functionality to
   analyze the obtained line coverage against the Smatch report. Using
   the following command, you can generate a file
   (traces/smatch\_match.lst) containing the lines from the Smatch
   report that the current fuzzing campaign has managed to reach. Run
   the Smatch analysis using:

   .. code-block:: bash

      ./fuzz.sh smatch /dev/shm/$USER_tdfl

   For a more complete mapping of the PT trace to line coverage, we
   have included functionality to augment the line coverage with
   information obtained using Ghidra. For example, if you want to make
   sure that code lines in in-lined functions are also considered, run
   the previous command, but set the environmental variable
   USE\_GHIDRA=1. E.g.:

   .. code-block:: bash

      USE_GHIDRA=1 ./fuzz.sh smatch /dev/shm/$USER_tdfl

We have included a script (`run\_experiments.py <https://github.com/intel/ccc-linux-guest-hardening/blob/master/bkc/kafl/run_experiments.py>`_) that automatically runs
these three steps for all the different relevant boot time harnesses.


Setup Instructions
-------------------

The full setup instructions for our kAFL-based fuzzing setup can be found at
https://github.com/intel/ccc-linux-guest-hardening


Fuzzing Kernel Runtime
======================

Fuzzing the TD Guest Kernel at runtime is relevant for any code paths that are
not exercised during boot or exercised during runtime with different context.
Finding a way to reliably activate these code paths can be more difficult as an
appropriate `stimulus` must be found. We present multiple options for finding
a stimulus program and then fuzzing untrusted host/VMM inputs in context of that
stimulus.

在运行时对 TD 客户内核进行模糊测试与任何在引导过程中未执行或在不同上下文中运行时执行的代码路径都相关。找到一种可靠地激活这些代码路径的方法可能更为困难，因为必须找到一个合适的刺激。我们提供了多种选项，用于找到一个刺激程序，然后在该刺激的上下文中对不受信任的主机/VMM输入进行模糊测试。

Fuzzing Stimulus
----------------

One challenge with TD guest kernel fuzzing is to create an
appropriate stimulus for the fuzzing process, i.e. to find a way to
reliably invoke the desired code paths in the TD guest kernel that
handle an input from the host/VMM. Without such stimulus, it is hard to
create good fuzzing coverage even for the code locations reported by the
Smatch static analyzer. We considered the following options:

-  **Write a set of dedicated tests that exercises the desired code
   paths**. The obvious downside of this approach is that it is very
   labor-intensive and manual. Also, the Smatch static analyzer list of
   findings goes well beyond 1500 unique entries; this approach does not
   scale since some of the tests might have to be modified manually as
   the mainline Linux kernel keeps developing.

-  **Use existing test suites for kernel subsystems.** This approach
   works well for the cases when a certain type of operation is known to
   eventually trigger an input from the host/VMM. Examples include Linux
   Test Project (LTP), as well as networking and filesystem test suites
   (netperf, stress-ng, perf-fuzzer). The challenge here is to identify test programs
   that trigger all the desired code paths. **Todo:** put a coverage info +
   refer to section for usermode tracing/fuzzing for how to find/test
   own stimulus.

-  **Automatically produced stimulus corpus.** An alternative way of
   using existing test suites or creating new ones can be a method that
   would programmatically exercise the existing TD guest kernel runtime
   code paths and produce a set of programs that allow invocation of the
   paths that lead to obtaining an input from the host/VMM. Fortunately,
   the Linux kernel has a well-known tool for exercising the kernel in
   runtime – Syzkaller fuzzer. While being a fuzzing tool that was
   originally created to test the robustness of ring 3 to ring 0
   interfaces, Syzkaller fuzzer can be used to automatically generate a
   set of stimulus programs once it is modified to understand whenever a
   code path that triggers an input from the host/VMM is invoked.
   However, the biggest problem with using Syzkaller in this way is to
   create a bias towards executing syscalls that would end up consuming
   the input from the host/VMM. This remains a direction for future
   research.


对 TD 客户内核进行模糊测试的一个挑战是创建一个适当的刺激，即找到一种可靠地调用 TD 客户内核中处理来自主机/VMM 输入的代码路径的方法。没有这样的刺激，即使对 Smatch 静态分析器报告的代码位置也难以创建良好的模糊测试覆盖率。我们考虑了以下选项：

1. 编写一套专门的测试来执行所需的代码路径。这种方法的明显缺点是它非常耗时且手动操作。此外，Smatch 静态分析器的发现列表超过了 1500 个独特条目；由于主线 Linux 内核不断发展，这种方法无法扩展，因为某些测试可能需要手动修改。

2. 使用现有的内核子系统测试套件。这种方法适用于当已知某种操作最终会触发来自主机/VMM 的输入的情况。例如 Linux 测试项目（LTP）、网络和文件系统测试套件（netperf、stress-ng、perf-fuzzer）。这里的挑战是确定可以触发所有所需代码路径的测试程序。待办事项：添加覆盖信息 + 引用用户模式跟踪/模糊测试的部分，以找到/测试自己的刺激。

3. 自动产生的刺激语料库。使用现有测试套件或创建新的测试套件的另一种方法可以是一种能够以编程方式执行现有 TD 客户内核运行时代码路径并生成一组允许调用导致从主机/VMM 获取输入的路径的程序的方法。幸运的是，Linux 内核拥有一个著名的工具用于在运行时执行内核 - Syzkaller 模糊测试工具。尽管 Syzkaller 最初是为测试环 3 到环 0 接口的鲁棒性而创建的模糊测试工具，但一旦修改为了解何时调用触发来自主机/VMM 输入的代码路径，它可以用于自动生成一组刺激程序。然而，以这种方式使用 Syzkaller 的最大问题是创建偏向于执行最终消费来自主机/VMM 输入的系统调用的偏差。这仍然是未来研究的方向。



Simple Fuzzer Hooks
--------------------

This simple fuzzer defines the basic fuzzer structure and the fuzzing
injection input hooks that can be used by more advanced fuzzers (and in
our case, used by the kAFL fuzzer) to supply the fuzzing input to the TD
guest kernel. The fuzzing input is consumed using the tdx\_fuzz() function
that is called right after the input has been consumed from the host
using the **TDG.VP.VMCALL** CPU interface.

The fuzzing input that is used by the basic fuzzer is a simple mutation
using random values and shifts of the actual supplied input from the
host/VMM. The algorithm to produce the fuzzing input can be found in
\_\_tdx\_fuzz() from arch/x86/kernel/tdx-fuzz.c. The main limitation of
this fuzzing approach is an absence of any feedback during the fuzzing
process, as well as an inability to recover from kernel crashes or
hangs.

The simple fuzzer exposes several statistics and input injection options via
debugfs. **TODO** Refer documentation as part of Linux kernel sources.



这个简单的模糊测试工具定义了基本的模糊测试结构和模糊测试注入输入钩子，这些钩子可以被更高级的模糊测试工具使用（在我们的案例中，由 kAFL 模糊测试工具使用）来向 TD 客户内核提供模糊测试输入。模糊测试输入使用 tdx_fuzz() 函数消费，该函数在从主机使用 TDG.VP.VMCALL CPU 接口消费输入之后立即调用。

基本模糊测试工具使用的模糊测试输入是使用随机值和实际供应来自主机/VMM 的输入的移位进行简单变异。生成模糊测试输入的算法可以在 arch/x86/kernel/tdx-fuzz.c 的 __tdx_fuzz() 中找到。这种模糊测试方法的主要限制是在模糊测试过程中缺乏任何反馈，以及无法从内核崩溃或挂起中恢复。

简单的模糊测试工具通过 debugfs 暴露了几个统计和输入注入选项。待办事项 参考 Linux 内核源代码的文档。




KF/x DMA Fuzzing
-----------------

Overview
~~~~~~~~

DMA shared memory is designed to be accessible by the host hypervisor to
facilitate fast I/O operations. DMA is setup using the Linux kernel’s
DMA API and the allocated memory regions are then used by various
drivers to facilitate I/O for disk, network, and console connections via
the VirtIO protocol. The goal of using the KF/x fuzzer on these DMA
memory regions is to identify issues in these drivers and the VirtIO
protocol that may lead to security issues.

To fuzz the code that interacts with DMA memory, do the following:

#. Capture VM snapshot when DMA memory read access is performed

#. Transfer VM snapshot to KF/x fuzzing host

#. Identify stop-point in the snapshot

#. Fuzz target using KF/x


DMA共享内存被设计为可以被宿主虚拟机管理程序访问，以便于快速I/O操作。DMA是通过Linux内核的DMA API设置的，分配的内存区域随后被各种驱动程序使用，以便通过VirtIO协议实现磁盘、网络和控制台连接的I/O。在这些DMA内存区域上使用KF/x模糊测试工具的目标是识别这些驱动程序和VirtIO协议中可能导致安全问题的问题。

要对与DMA内存交互的代码进行模糊测试，请执行以下操作：

1. 当执行DMA内存读取访问时，捕获VM快照

2. 将VM快照传输到KF/x模糊测试主机

3. 确定快照中的停止点

4. 使用KF/x对目标进行模糊测试。

.. figure:: images/kf-x-overview.png
   :width: 5.86458in
   :height: 3.29883in

   Figure 5. KF/x overview

Details
~~~~~~~

A. As the memory underpinning DMA is regular RAM, the guest-physical
   address is bound to run through the MMU’s Second Layer Address
   Translation via the Extended Page Tables (EPT). This allows us to
   restrict the EPT permissions and remove read-access rights from the VM.
   By removing EPT access rights of the memory regions designated to be
   DMA, the hypervisor gets a page-fault notification of all code-locations
   that interact with DMA memory. The `Bitdefender KVM VMI
   patch-set <https://github.com/kvm-vmi>`__ is used for this
   introspection.

   DMA regions are identified by hooking the Linux kernel’s DMA API via
   hypervisor-level breakpoint injection. By injecting a breakpoint into
   the DMA API responsible for mapping and unmapping memory, we can track
   which memory pages are designated to be DMA. The VM is booted with this
   monitoring enabled from the start and the EPT permissions are
   automatically restricted for all pages that are currently DMA mapped.

   As DMA accesses are very frequent, the number of snapshots taken are
   reduced by observing the call-stack leading to the DMA access. For this,
   the kernel is compiled with stack frame pointers enabled. By hashing the
   four top-level functions on the call-stack, we identify whether a given
   DMA access is performed under a unique context or not (such as a
   particular system-call, kernel thread, etc.).

   The faulting instruction is then emulated by the hypervisor to allow the
   DMA access to continue without the kernel getting stuck trying to access
   memory.

B. Snapshots are transferred to KF/x fuzzing hosts running on Xen.
   Snapshots are loaded into VM-shells by transplanting the snapshots’
   memory and vCPU context.

C. The transplanted snapshot is executed up to a limited number of
   instructions (usually between 100k-250k) and logged to a file.
   Cross-reference the log with stacktrace to see how far back up the stack
   the execution reached. Place a breakpoint at that address.

D. KF/x is set up to fuzz the entire DMA page (4096 bytes) where the
   memory access was captured. The fuzzer is set to log any fuzzed input
   that leads to KASAN, UBSAN, or panic in the VM.


A. 由于DMA所依托的内存是常规RAM，客户物理地址必须通过MMU的第二层地址转换（Extended Page Tables, EPT）进行处理。这使我们能够限制EPT权限，并从虚拟机中移除读取权限。通过移除被指定为DMA的内存区域的EPT访问权限，当与DMA内存交互的代码位置发生时，虚拟机管理程序将收到页面错误通知。我们使用Bitdefender KVM VMI补丁集 <https://github.com/kvm-vmi>__ 进行这种内省。

通过在虚拟机管理程序级别注入断点来挂钩Linux内核的DMA API，识别DMA区域。通过向负责映射和解映射内存的DMA API注入断点，我们可以追踪哪些内存页面被指定为DMA。虚拟机从开始就启用此监控，并自动限制所有当前映射为DMA的页面的EPT权限。

由于DMA访问非常频繁，通过观察导致DMA访问的调用堆栈，减少了快照的数量。为此，内核被编译时启用了堆栈帧指针。通过散列调用堆栈上的四个顶层函数，我们确定给定的DMA访问是否在独特的上下文下执行（例如特定的系统调用、内核线程等）。

然后由虚拟机管理程序模拟故障指令，允许DMA访问继续，而不会让内核因尝试访问内存而卡住。

B. 快照被转移到运行在Xen上的KF/x模糊测试主机。通过移植快照的内存和vCPU上下文，将快照加载到VM-shell中。

C. 移植后的快照被执行，直到限制的指令数（通常在100k-250k之间），并记录到文件中。将日志与堆栈跟踪进行交叉引用，查看执行达到堆栈的多远处。在该地址处设置断点。

D. KF/x设置为对捕获内存访问的整个DMA页面（4096字节）进行模糊测试。模糊测试器被设置为记录任何导致虚拟机中发生KASAN、UBSAN或panic的模糊输入。



Setup instructions
~~~~~~~~~~~~~~~~~~

`Virtio snapshotting with KVM VMI · intel/kernel-fuzzer-for-xen-project
Wiki
(github.com) <https://github.com/intel/kernel-fuzzer-for-xen-project/wiki/Virtio-snapshotting-with-KVM-VMI>`__


kAFL Stimulus Fuzzing
---------------------

.. figure:: images/kAFL-runtime-overview.png
   :width: 3.60417in
   :height: 3.98958in

   Figure 6. kAFL runtime fuzzing overview. 1) start of fuzzing 2)
   input fuzz buffer from host 3) stimulus is consumed from userspace
   4) MSR/PIO/MMIO causes a #VE 5) the agent injects a value obtained
   from 6) the input buffer 7) finally, reporting back the status to
   the host (crash/ hang/ ok)


The kAFL agent described earlier can also be used to trace and fuzz custom
stimulus programs from userspace. The kAFL setp for userspace fuzzing uses to
following additional components:

-  kAFL agent exposes a userspace interface via debugfs. The interface
   offers similar controls to those used to implement boot-time harneses
   inside the kernel, i.e. start/stop as well as basic statistics.

-  The VM must be started with a valid rootfs, such as an initrd that
   contains the stimulus program. The kernel is configured with
   CONFIG\_TDX\_FUZZ\_HARNESS\_NONE; it boots normally and launches the
   designated ‘init’ process. Fuzzer configuration and control is done
   via debugfs.

-  To avoid managing a large range of filesystems, kAFL offers a
   ‘sharedir’ option that allows to download files into the guest at
   runtime. This way, the rootfs only contains a basic loader while
   actual execution is driven by scripts and programs on the Host.
   Communication is done using hypercalls and works independently of
   virtio or other guest drivers.


前面提到的kAFL代理也可以用于追踪和模糊测试来自用户空间的自定义刺激程序。用户空间模糊测试的kAFL设置使用以下附加组件：

1. kAFL代理通过debugfs暴露用户空间接口。该接口提供与内核中实现启动时控制程序类似的控制功能，即启动/停止以及基本统计数据。

2. 虚拟机必须使用有效的rootfs启动，例如包含刺激程序的initrd。内核配置为CONFIG_TDX_FUZZ_HARNESS_NONE；它正常启动并启动指定的‘init’进程。模糊测试器的配置和控制通过debugfs完成。

3. 为避免管理大量文件系统，kAFL提供了一个‘sharedir’选项，允许在运行时将文件下载到客户机中。这样，rootfs只包含基本的加载程序，而实际的执行由主机上的脚本和程序驱动。通信通过hypercalls完成，独立于virtio或其他客户机驱动程序。


Harness Setup
~~~~~~~~~~~~~

As with the other runtime fuzzing setups, the kAFL setup requires an
adequate “stimulus” to trigger kernel code paths that consume data from
the untrusted host/VMM (either using **TDG.VP.VMCALL**-based interface
or virtIO DMA shared memory). We setup kAFL to run any desired userspace
binaries as stimulus input, using a flexible bash script to initialize
snapshotting & stimulus execution from /sbin/init.

The usermode harness that is downloaded and launched by the loader can
be any script or binary and may also act as an intermediate loader or
even compiler of further input. The main difference from regular VM
userspace is that the harness eventually enables the fuzzer, at which
point the kAFL/Qemu frontend creates the initial VM snapshot and
provides a first candidate payload to the kAFL agent. Once the snapshot
loop has started, execution is traced for coverage feedback and the
userspace is fully reset after timeout, crashes, or when the “done”
event is signaled via debugfs.

与其他运行时模糊测试设置一样，kAFL设置也需要一个合适的‘刺激’来触发消耗来自不受信任主机/VMM数据的内核代码路径（无论是使用TDG.VP.VMCALL接口还是virtIO DMA共享内存）。我们设置kAFL以运行任何所需的用户空间二进制文件作为刺激输入，使用灵活的bash脚本从/sbin/init初始化快照和刺激执行。

由加载器下载和启动的用户模式控制程序可以是任何脚本或二进制文件，也可以充当中间加载器甚至是进一步输入的编译器。与常规VM用户空间的主要区别在于，控制程序最终会启用模糊测试器，此时kAFL/Qemu前端会创建初始的VM快照，并向kAFL代理提供第一个候选负载。一旦快照循环开始，执行将被追踪以获得覆盖反馈，并且在超时、崩溃或通过debugfs发出‘完成’事件信号后，用户空间将完全重置。


Example harness using a stimulus.elf program:

.. code-block:: bash

      #!/bin/bash
      KAFL_CTL=/sys/kernel/debug/kafl
      hget stimulus.elf # fetch test binary from host
      echo "[*] kAFL agent status:"
      grep . $KAFL_CTL/*
      # "start" signal initializes agent and triggers snapshot
      echo "start" > $KAFL_CTL/control
      # execute the stimulus, redirecting outputs to host hprintf log
      ./stimulus.elf 2>&1 |hcat
      # if we have not crashed, signal "success" and restore snapshot
      echo "done" > $KAFL_CTL/control


Detailed setup and scripts to generate small rootfs/initrd:
https://github.com/intel/ccc-linux-guest-hardening/tree/master/bkc/kafl/userspace

More sophisticated “harness” for randomized stimulus execution:
https://github.com/intel/ccc-linux-guest-hardening/tree/master/bkc/kafl/userspace/sharedir_template/init.sh

Enabling additional kernel drivers
==================================

The reference TDX guest kernel implementation provided for the `Linux SW stack for
Intel TDX <https://github.com/intel/tdx-tools>`_ only enables a small set of
virtio drivers that are essential for the TDX guest basic functionality. These
drivers have been hardened using the methodology described in this document,
but naturally different deployment scenarios and use cases for the TDX will
require many more additional drivers to be enabled in the TDX guest kernel.

This section provides guidance on how to use the methodology presented
in this document for adding and hardening a new driver for the TDX guest kernel.

In order to explain better on how to perform the below steps, we will
use virtio-vsock driver as an example. This driver was the last one to
be enabled and hardened
for the `Linux SW stack for Intel TDX <https://github.com/intel/tdx-tools>`_.
Its primary usage in TDX guest kernel is to communicate with the host to
request converting a local TDX attestation report into a remotely verifiable
TDX attestation quote.

提供的Intel TDX的Linux软件堆栈<https://github.com/intel/tdx-tools>_的参考TDX来宾内核实现仅启用了对TDX来宾基本功能至关重要的一小部分virtio驱动程序。这些驱动程序已使用本文档中描述的方法进行加固，但显然，不同的部署场景和TDX的用例需要在TDX来宾内核中启用更多的其他驱动程序。

本节提供了关于如何使用本文档中介绍的方法为TDX来宾内核添加和加固新驱动程序的指南。

为了更好地解释以下步骤，我们将以virtio-vsock驱动程序为例。这个驱动程序是最后一个为Intel TDX的Linux软件堆栈<https://github.com/intel/tdx-tools>_启用和加固的驱动程序。它在TDX来宾内核中的主要用途是与主机通信，以请求将本地的TDX认证报告转换为可远程验证的TDX认证报价。


Identify the device/driver pair
-------------------------------

The first step includes locating the source code of a target driver in
the Linux kernel tree, understanding the bus that this driver
is registered for (typically it would be a pci or acpi bus), as well as
how the driver registration is done, how to perform functional testing
for this driver and any higher-level interface abstractions present.

**Example**. For our :code:`virtio-vsock` driver example, the source code of this
driver is located at `/net/vmw_vsock/virtio_transport.c <https://github.com/IntelLabs/kafl.linux/blob/kafl/fuzz-5.15-4/net/vmw_vsock/virtio_transport.c>`_ and the driver
registers itself on the virtio bus (an abstraction level over the pci bus)
using `register_virtio_driver() <https://github.com/IntelLabs/kafl.linux/blob/kafl/fuzz-5.15-4/net/vmw_vsock/virtio_transport.c#L754>`_.


第一步包括在Linux内核树中找到目标驱动程序的源代码，了解该驱动程序注册的总线（通常是PCI或ACPI总线），以及如何进行驱动程序注册、如何执行该驱动程序的功能测试以及任何高层接口抽象。

示例。对于我们的 :code:virtio-vsock 驱动程序示例，该驱动程序的源代码位于 /net/vmw_vsock/virtio_transport.c <https://github.com/IntelLabs/kafl.linux/blob/kafl/fuzz-5.15-4/net/vmw_vsock/virtio_transport.c>，并且该驱动程序使用 register_virtio_driver() <https://github.com/IntelLabs/kafl.linux/blob/kafl/fuzz-5.15-4/net/vmw_vsock/virtio_transport.c#L754> 在virtio总线上注册（这是PCI总线的抽象层）。



Perform code audit
------------------

In this step, the source code of the driver
is manually audited to determine the input points where the untrusted data
from the host or `VMM` is consumed and how this data is being processed.
In order to facilitate the manual audit, the :code:`check_host_input` smatch pattern can
be used to identify these input points. For that, a smatch run can be done on
an individual driver source file using :code:`kchecker` command.

**Example**. The below command line for :code:`virtio-vsock` driver assumes
that you have
a smatch instance with the :code:`check_host_input` pattern installed at
:code:`~/smatch` folder and the command is invoked from the kernel source tree root.
For the instructions on how to install smatch please consult
`README.md <https://github.com/intel/ccc-linux-guest-hardening/blob/master/bkc/audit/README.md>`_


在此步骤中，手动审核驱动程序的源代码，以确定从主机或VMM获取不受信任数据的输入点，并检查这些数据是如何处理的。为了简化手动审核，可以使用:code:check_host_input smatch模式来识别这些输入点。为此，可以使用:code:kchecker命令在单个驱动程序源文件上运行smatch。

示例。以下是针对:code:virtio-vsock驱动程序的命令行，假设你在:code:~/smatch文件夹中安装了带有:code:check_host_input模式的smatch实例，并且命令是从内核源代码树的根目录调用的。有关如何安装smatch的说明，请参考
README.md <https://github.com/intel/ccc-linux-guest-hardening/blob/master/bkc/audit/README.md>_


.. code-block:: bash

      ~/smatch_scripts/kchecker net/vmw_vsock/virtio_transport.c > driver_results

The :code:`driver_results` output file will contain the list of input points
and the limited
propagation information:

.. code-block:: shell

   net/vmw_vsock/virtio_transport.c:305 virtio_transport_tx_work() error:
   {8890488479003397221} 'check_host_input' read from the host using function
   'virtqueue_get_buf' to a non int type local variable 'pkt', type is struct virtio_vsock_pkt*;   
   net/vmw_vsock/virtio_transport.c:306 virtio_transport_tx_work() error:
   {5556237559821482352} 'check_host_input' propagating a tainted value from
   the host 'pkt' into a function 'virtio_transport_free_pkt';
   net/vmw_vsock/virtio_transport.c:305 virtio_transport_tx_work() warn:
   {8890488479003397221} 'check_host_input' potential read from the host using
   function 'virtqueue_get_buf';
   net/vmw_vsock/virtio_transport.c:375 virtio_vsock_update_guest_cid() error:
   {7572251756130242} 'check_host_input' propagating a tainted value from
   the host 'guest_cid' into a function 'get';
   net/vmw_vsock/virtio_transport.c:377 virtio_vsock_update_guest_cid() error:
   {16638257021812442297} 'check_host_input' propagating read value from
   the host 'guest_cid' into a different complex variable 'vsock->guest_cid';
   net/vmw_vsock/virtio_transport.c:410 virtio_transport_event_work() error:
   {8890488479003397221} 'check_host_input' read from the host using function
   'virtqueue_get_buf' to a non int type local variable 'event', type is struct virtio_vsock_event*;
   net/vmw_vsock/virtio_transport.c:412 virtio_transport_event_work() error:
   {8840682050757106252} 'check_host_input' propagating a tainted value from
   the host 'event' into a function 'virtio_vsock_event_handle';
   net/vmw_vsock/virtio_transport.c:414 virtio_transport_event_work() error:
   {83481497696856778} 'check_host_input' propagating a tainted value from
   the host 'event' into a function 'virtio_vsock_event_fill_one';
   net/vmw_vsock/virtio_transport.c:410 virtio_transport_event_work() warn:
   {8890488479003397221} 'check_host_input' potential read from the host
   using function 'virtqueue_get_buf';
   net/vmw_vsock/virtio_transport.c:541 virtio_transport_rx_work() error:
   {8890488479003397230} 'check_host_input' read from the host using function
   'virtqueue_get_buf' to a non int type local variable 'pkt', type is struct virtio_vsock_pkt*;
   net/vmw_vsock/virtio_transport.c:551 virtio_transport_rx_work() error:
   {5556237559821482370} 'check_host_input' propagating a tainted value from
   the host 'pkt' into a function 'virtio_transport_free_pkt';
   net/vmw_vsock/virtio_transport.c:556 virtio_transport_rx_work() error:
   {5857033014461230228} 'check_host_input' propagating a tainted value from
   the host 'pkt' into a function 'virtio_transport_deliver_tap_pkt';
   net/vmw_vsock/virtio_transport.c:557 virtio_transport_rx_work() error:
   {8453424129492944817} 'check_host_input' propagating a tainted value from
   the host 'pkt' into a function 'virtio_transport_recv_pkt';

Given this information the manual code audit can be performed by looking at each
reported entry in the source code to determine whenever the input consumed
from host or `VMM` is processed securely. Please consult section `Static Analyzer and Code Audit`_
for more information on how to interpret each reported entry and how to perform
manual analysis. The output of this step is a list of entries that are marked
'concern' that would require patches to be created in order to harden
the given driver based on the manual code audit step.


根据这些信息，可以通过查看源代码中的每个报告条目来进行手动代码审核，以确定从主机或VMM获取的输入是否安全处理。有关如何解释每个报告条目和如何进行手动分析的更多信息，请参考“静态分析器和代码审核”部分。此步骤的输出是一个标记为'concern'的条目列表，这些条目需要创建补丁，以基于手动代码审核步骤加固给定的驱动程序。


Perform driver fuzzing
----------------------

Ideally each code location reported by the smatch
in step 2 needs to be exercised by using either `kafl` or `kfx` fuzzers (or both).
However, if resource or timing is very limited, the fuzzing can be
primary focused
only on the 'concern' entries from the step 2 or on any other entries
that are considered potentially problematic (complex parsing of data, many call
chains, etc.).
The typical reported input locations can be divided into two groups:
driver initialization
code (init and probe functions) and runtime operation. The first group would be
the easiest one to reach by a fuzzer since it does not require any
external stimulus:
it only requires a creation of a separate fuzzing harness. The second
one ideally
requires a functional test suite to be run to exercise the driver
functionality as a stimulus.
However, in the absence of such a test suite, a set of simple manual
tests can be
created or certain userspace commands/operations performed that trigger
invocation of the functions reported by smatch in step 2. Setting up
the driver fuzzing can also be very beneficial even in cases when
smatch does not report any hits in driver’s init or probe functions,
because smatch can miss some host input consumption points in some
cases and fuzzing can help discover such cases.

**Example**. Enabling fuzzing targets like the :code:`virtio-vsock` driver
requires some manual work and modifications of the fuzzing setup (as
opposite to more straightforward examples like :code:`virtio-net` or
:code:`virtio-console`) and below steps explain how to add support for such a
target. In a nutshell, :code:`virtio-vsock` sets up a socket on the host or `VMM`,
allowing a host process to setup a direct socket connection to the
guest VM over `VirtIO`. For fuzzing, this requires some initial setup in
the host, as well as establishing a connection from the guest.
It is also important to make sure that the targeted device is allowed
by the device filter when performing the fuzzing. See  
`Enable driver in the TDX filter``  below for the instructions. 

**Host steps**. First, the `VMM` host kernel must support :code:`VSOCK`. The
corresponding kernel module can be loaded using :code:`modprobe vhost_vsock`.
If this fails, it might be required to install a
different kernel which has :code:`CONFIG_VHOST_VSOCK` set. When the
:code:`vhost_vsock` driver is enabled, a device shall appear at
:code:`/dev/vhost-vsock`. Its default permissions might be insufficient for
`QEMU` to access, but it can be fixed by executing :code:`chmod 0666 /dev/vhost-vsock`.
Now that the :code:`vhost-vsock` device is available to
`QEMU`, the device for the guest VM can be enabled by appending the
string :code:`-device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid=3` to
QEMU options. The guest-cid value is a connection identifier that
needs to be unique for the system. In other words, when fuzzing with
multiple workers, each `QEMU` instance must use a separate guest-cid.
For kAFL we have added some syntax magic to allow for these
kinds of situations. In your :code:`kafl_config.yaml` (by default found in
:code:`$BKC_ROOT/bkc/kafl/kafl_config.yaml`),  the following string can be
appended to the :code:`qemu_base` entry: :code:`-device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid={QEMU_ID + 3}`.
The expression :code:`QEMU_ID + 3`, will evaluate to the `QEMU` worker instance id
(which is unique) plus 3. We need to add 3, since the vsock guest cid
range starts at 3. `CIDs` 0,1,2 are reserved for the hypervisor,
generally reserved, and reserved for the host respectively. Now each
fuzzing worker instance should get its own unique `CID`, allowing a
connection to be made from the guest to the host. Finally, to be able
to test vsock and setup connections, the :code:`socat` utility can be used.
While :code:`socat` can be already installed on your fuzzing system, the socat
vsock support is a recent addition and it might be required to
download or build a more recent version of socat to enable this
functionality. Pre-built binaries and the source code is available at
`socat project page <http://www.dest-unreach.org/socat/>`` To test
whether the installed :code:`socat` supports vsock execute: :code:`socat VSOCK-LISTEN:8089,fork`.


理想情况下，第2步中smatch报告的每个代码位置都需要使用kafl或kfx模糊测试工具（或两者）进行测试。然而，如果资源或时间非常有限，模糊测试可以主要集中在第2步中标记为'concern'的条目或其他被认为可能存在问题的条目（例如，复杂的数据解析，许多调用链等）上。通常报告的输入位置可以分为两类：驱动程序初始化代码（init和probe函数）和运行时操作。第一类最容易被模糊测试工具触及，因为它不需要任何外部刺激：只需创建一个单独的模糊测试环境。第二类则理想情况下需要运行功能测试套件以作为驱动程序功能的刺激。然而，在没有此类测试套件的情况下，可以创建一组简单的手动测试或执行某些用户空间命令/操作以触发第2步中smatch报告的函数的调用。即使在smatch未报告任何驱动程序的init或probe函数中的命中时，设置驱动程序模糊测试也是非常有益的，因为smatch在某些情况下可能会遗漏某些主机输入消费点，而模糊测试可以帮助发现这些情况。

示例。启用类似于:code:virtio-vsock驱动程序的模糊测试目标需要一些手动工作和模糊测试设置的修改（与更直接的示例如:code:virtio-net或:code:virtio-console相反），以下步骤说明了如何为此目标添加支持。简而言之，:code:virtio-vsock在主机或VMM上设置了一个套接字，允许主机进程通过VirtIO设置与来宾虚拟机的直接套接字连接。对于模糊测试，这需要在主机中进行一些初始设置，并从来宾端建立连接。在执行模糊测试时，确保目标设备被设备过滤器允许也很重要。有关说明，请参阅下文的“启用TDX过滤器中的驱动程序”。

主机步骤。首先，VMM主机内核必须支持:code:VSOCK。可以使用:code:modprobe vhost_vsock加载相应的内核模块。如果失败，可能需要安装一个设置了:code:CONFIG_VHOST_VSOCK的不同内核。当:code:vhost_vsock驱动程序启用后，一个设备将出现在:code:/dev/vhost-vsock。默认权限可能不足以让QEMU访问，但可以通过执行:code:chmod 0666 /dev/vhost-vsock来修复。现在可以通过向QEMU选项附加字符串:code:-device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid=3来为来宾虚拟机启用设备。guest-cid值是一个系统唯一的连接标识符。换句话说，在多个工作者的模糊测试中，每个QEMU实例必须使用一个独特的guest-cid。对于kAFL，我们添加了一些语法魔法来允许这种情况。在您的:code:kafl_config.yaml中（默认位于:code:$BKC_ROOT/bkc/kafl/kafl_config.yaml），可以将以下字符串附加到:code:qemu_base条目：:code:-device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid={QEMU_ID + 3}。表达式:code:QEMU_ID + 3将评估为QEMU工作实例ID（这是唯一的）加3。我们需要加3，因为vsock客人cid范围从3开始。CID 0、1、2分别保留给虚拟机监视器，一般保留和保留给主机。现在每个模糊测试工作实例应该有自己唯一的CID，允许从来宾端到主机的连接。最后，为了能够测试vsock和设置连接，可以使用:code:socat实用程序。虽然:code:socat可能已经安装在您的模糊测试系统上，但socat的vsock支持是最近添加的功能，可能需要下载或构建更近期的socat版本以启用此功能。在socat项目页面 <http://www.dest-unreach.org/socat/>中提供了预构建的二进制文件和源代码。要测试安装的:code:socat是否支持vsock，请执行:code:socat VSOCK-LISTEN:8089,fork。



To summarize, these are the main steps to be performed on the host:

.. code-block:: bash

	modprobe vhost_vsock
	chmod 0666 /dev/vhost-vsock
	qemu: -device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid=3

**Guest steps**. 

The next step in enabling :code:`virtio-vsock` fuzzing is to
set up the kAFL userspace fuzzing harness in the following way.


First, the guest kernel needs to be compiled with :code:`vsock` support
(:code:`CONFIG_VIRTIO_VSOCKET=y` and :code:`CONFIG_VHOST_VSOCK=y`). Alternatively, it
can be also enabled as a kernel module, but this will require an
additional step to load the module later. To make things easier, just
build the drivers as built-in.

Since we have opted to use the socat tool, the socat utility needs to
be enabled in guest’s busybox :code:`initrd.cpio.gz`. It can be done during
the socat built by either setting :code:`BR2_PACKAGE_SOCAT /` in the
:code:`bkc/kafl/userspace/buildroot.config`, or alternatively in
:code:`$BKC_ROOT/buildroot-2021.11` use :code:`make menuconfig` navigate to the
right menu entry, save the config, and then build using :code:`make`.

Finally, the following steps will add the correct kAFL userspace
harness. In :code:`$BKC_ROOT/sharedir`, edit your :code:`init.sh` to include the
following snippet early in the script.


启用 :code:virtio-vsock 模糊测试的下一步是以下方式设置 kAFL 用户空间模糊测试框架。

首先，需要在支持 :code:vsock 的情况下编译来宾内核（:code:CONFIG_VIRTIO_VSOCKET=y 和 :code:CONFIG_VHOST_VSOCK=y）。或者，也可以将其作为内核模块启用，但这将需要额外的步骤来加载模块。为了简化操作，可以将驱动程序内置。

由于我们选择使用 socat 工具，因此需要在来宾的 busybox :code:initrd.cpio.gz 中启用 socat 实用程序。可以在构建 socat 时通过设置 :code:BR2_PACKAGE_SOCAT / 在 :code:bkc/kafl/userspace/buildroot.config，或者在 :code:$BKC_ROOT/buildroot-2021.11 中使用 :code:make menuconfig 导航到正确的菜单项，保存配置，然后使用 :code:make 进行构建。

最后，以下步骤将添加正确的 kAFL 用户空间框架。在 :code:$BKC_ROOT/sharedir 中，编辑您的 :code:init.sh，在脚本的早期阶段包括以下片段。”

.. code-block:: bash

	mount -t debugfs none /sys/kernel/debug/
	KAFL_CTL=/sys/kernel/debug/kafl
	echo “VSOCK fuzzing harness” | hcat
	echo "start"  > $KAFL_CTL/control
	socat - VSOCK-CONNECT:2:8089
	echo "done"  > $KAFL_CTL/control

Now it should be possible to start up a new `VSOCK` harness by first,
start listening on the host using :code:`socat VSOCK-LISTEN:8089,fork –`,
and then start kAFL (make sure it’s using HARNESS_NONE, as always when
using userspace harnesses) using :code:`fuzz.sh run linux-guest --debug -p1 --sharedir sharedir/`.
You should see the text :code:`VSOCK fuzzing harness`
appear in your kAFL process.


现在应该可以启动一个新的 VSOCK 框架，首先，在主机上使用 :code:socat VSOCK-LISTEN:8089,fork – 启动监听，然后启动 kAFL（确保它使用 HARNESS_NONE，因为在使用用户空间框架时总是如此），使用 :code:fuzz.sh run linux-guest --debug -p1 --sharedir sharedir/。您应该在您的 kAFL 进程中看到文本 :code:VSOCK fuzzing harness 出现。


To summarize these steps can be executed to start a `VSOCK` harness:

On the guest:

.. code-block:: bash

	socat VSOCK-LISTEN:8089,fork –

On the host:

.. code-block:: bash

	socat - vsock-accept:3:8089

On the guest:

.. code-block:: bash

	socat - VSOCK-CONNECT:2:8089

On the host:

.. code-block:: bash

	socat VSOCK-LISTEN:8089,fork –

It is also likely that in the above-mentioned setup the kAFL fuzzer
will not make any progress. This is due to the fact that the inputs
are not stable. This happens due to the fact that an external process
is part of the fuzzing setup. If you encounter this issue, you might
need to modify kAFL slightly. In the function :code:`execute()` in
:code:`$BKC_ROOT/kafl/fuzzer/kafl_fuzzer/worker/worker.py`, when a value is
assigned to the variable :code:`stable`, make sure to overwrite this with
True. It is also possible to add a custom command line flag enabling
this feature to the kAFL settings in
:code:`$BKC_ROOT/kafl/fuzzer/kafl_fuzzer/common/config.py`.

The above example for the :code:`virtio-vsock` has demonstrated how to enable
fuzzing in a more complex driver setup scenario using a userspace kAFL
harness. The end output of the fuzzing step is a set of reproducible
crashes that a fuzzer finds for the given driver. The crashes needs to
be investigated and the ones that are determined to be real security
issues need to be fixed in the code.



在上述设置中，kAFL fuzzer 可能不会有任何进展。这是因为输入不稳定。这种情况是由于外部进程是fuzzing设置的一部分。如果遇到此问题，可能需要稍微修改 kAFL。在函数 :code:execute() 中的 :code:$BKC_ROOT/kafl/fuzzer/kafl_fuzzer/worker/worker.py 文件中，当给变量 :code:stable 赋值时，请确保将其覆盖为 True。也可以在 :code:$BKC_ROOT/kafl/fuzzer/kafl_fuzzer/common/config.py 中的 kAFL 设置中添加一个自定义命令行标志来启用此功能。

上述 :code:virtio-vsock 的示例展示了如何在使用用户空间 kAFL 框架的更复杂的驱动程序设置场景中启用 fuzzing。fuzzing 步骤的最终输出是一组 fuzzing 找到的可重现的崩溃。这些崩溃需要进行调查，并且确定为真正安全问题的部分需要在代码中修复。


Perform code fixes
------------------

Based on the above steps 2 and 3, a set of hardening patches
need to be created to fix the identified issues. We strongly encourage to submit
any such hardening patches to the mainline Linux kernel to ensure
everyone benefits
the joint hardened kernel, as well to get suggestions on the most
appropriate way of
fixing these issues. Also in order to verify that the issues have been
addressed by
respective patches, a new round of fuzzing needs to be performed to
verify that the
issues found in step 3 are not reproducible anymore.

Enable driver in the TDX filter
-------------------------------

When the driver code has been hardened and all
the patches are integrated and verified, the driver can be enabled in
the TDX guest by modifying
the allow list in the TDX driver filter code in `arch/x86/kernel/tdx-filter.c <https://github.com/IntelLabs/kafl.linux/blob/kafl/fuzz-5.15-4/arch/x86/kernel/tdx-filter.c>`_.

**Example**. For the virtio-vsock driver the following patch adds it
to the list of allowed devices on the virtio bus.

.. code-block:: diff

	Vsock driver has been audited, add it to the allow list in the TDX device
	filter.

	Signed-off-by: Alexander Shishkin <alexander.shishkin@linux.intel.com>
	---
	arch/x86/kernel/tdx-filter.c    | 1 +
	include/uapi/linux/virtio_ids.h | 1 +
	2 files changed, 2 insertions(+)

	diff --git a/arch/x86/kernel/tdx-filter.c b/arch/x86/kernel/tdx-filter.c
	index 47fda826aec4..fd759680bd2a 100644
	--- a/arch/x86/kernel/tdx-filter.c
	+++ b/arch/x86/kernel/tdx-filter.c
	@@ -64,6 +64,7 @@ struct pci_device_id pci_allow_ids[] = {
	  { PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_BLOCK) },
	  { PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_CONSOLE) },
	  { PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_9P) },
	+ { PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QUMRANET, VIRTIO1_ID_VSOCK) },
	  { 0, },
	};

	diff --git a/include/uapi/linux/virtio_ids.h b/include/uapi/linux/virtio_ids.h
	index a2fcb4681028..f592efd82450 100644
	--- a/include/uapi/linux/virtio_ids.h
	+++ b/include/uapi/linux/virtio_ids.h
	@@ -88,5 +88,6 @@
	#define VIRTIO1_ID_BLOCK 0x1042 /* transitional virtio block */
	#define VIRTIO1_ID_CONSOLE 0x1043 /* transitional virtio console */
	#define VIRTIO1_ID_9P 0x1049 /* transitional virtio 9p console */
	+ #define VIRTIO1_ID_VSOCK 0x1053 /* transitional virtio vsock transport */

	#endif /* _LINUX_VIRTIO_IDS_H */
	--
	2.25.1
