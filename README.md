# WinVisor

## Overview

In Windows 10 (version RS4), Microsoft introduced the Windows Hypervisor Platform (WHP) API. This API exposes Microsoft's built-in hypervisor functionality to user-mode Windows applications. In 2024, I used this API to create another project: a 16-bit MS-DOS emulator called DOSVisor. This project takes the concept further, and allows Windows x64 executables to be emulated within a virtualized environment.

The WHP API allows applications to create a virtual CPU, and map virtual memory from the host process directly into the guest's physical memory. The emulator uses this functionality to build a virtual environment which contains everything needed to execute a Windows user-mode process. This involves building up the memory space within the guest, including mapping the target executable and all DLL dependencies, followed by populating other internal data structures such as the `PEB`, `TEB`, `KUSER_SHARED_DATA`, etc.

Mapping the EXE and DLL dependencies into memory is a simple task, but accurately maintaining internal structures, such as the PEB, is more complex. These structures are large, mostly undocumented, and their contents can vary between Windows versions. Instead of manually building up the memory layout within the virtual environment, WinVisor launches a suspended instance of the target process and clones the entire address space into the guest. The IAT and TLS data directories are temporarily removed from the PE headers in memory to stop DLL dependencies from loading and to prevent TLS callbacks from executing before reaching the entry point. The process is then resumed, allowing the usual process initialization to continue until it reaches the entry point of the target executable, at which point the hypervisor launches and takes control.

As the WHP API only allows memory from the current process to be mapped into the guest, the main hypervisor logic is encapsulated within a DLL that gets injected into the target process.

At the present time, the emulator simply forwards all syscalls to the host OS and logs them to the console. However, the project provides a framework to easily facilitate syscall hooks if necessary.

## Usage

WinVisor has some limitations in its current form - the biggest one being that it currently only supports virtualizing a single thread. Other examples are described in further detail in the **Limitations** section below.

Despite these limitations, it still works well with many executables. It has been tested successfully against built-in Windows executables such as `cmd.exe`, `ping.exe`, and even GUI applications such as `mspaint.exe` and `notepad.exe` (although these only run partially virtualized as described later).

To launch WinVisor, simply execute the following command:
`WinVisor.exe <target_executable_path>`

Command-line parameters can also be specified for the target application, for example:
`WinVisor.exe c:\windows\system32\ping.exe 8.8.8.8`

If `[ERROR] Failed to initialise Windows Hypervisor Platform API` is displayed, please ensure that `Windows Hypervisor Platform` is installed and enabled in "Windows Features".

![cmd.exe running under WinVisor](https://github.com/x86matthew/WinVisor/blob/main/winvisor_screenshot.png?raw=true)
*(screenshot above shows WinVisor emulating `cmd.exe` within a virtualized environment)*

## Virtual CPU

The emulator creates a virtual CPU via WHP to execute the target binary. The virtual CPU operates almost exclusively in CPL3 (user-mode), except for a small bootloader that runs at CPL0 (kernel-mode) to initialize the CPU state before execution. The initialization process involves setting up the following aspects:

- Control registers (`CR0`, `CR3`, `CR4`, `XCR0`)
- MSRs (`MSR_EFER`, `MSR_LSTAR`, `MSR_STAR`, `MSR_GS_BASE`)
- GDT
- IDT
- TSS
- Initial segment selectors and register values
- Paging table (4-layer)

Once the initial CPU state has been set up, it switches to CPL3 via a `SYSRET` instruction and begins executing the target application.

The emulator handles both `SYSCALL` instructions and legacy (`INT 2E`) syscalls. To catch system calls performed via the `SYSCALL` instruction, the `MSR_LSTAR` value is set to a reserved placeholder address. This placeholder address exists in kernel space, ensuring that no conflicts occur with real user-mode memory within the process. When the virtual CPU attempts to execute the `SYSCALL` instruction, a page fault exception is generated, causing a VM exit which indicates to the host that a syscall is pending.

Legacy interrupt-based syscalls are handled in a very similar way. The IDT is pre-populated with a range of placeholder handler addresses, causing a VM exit when an interrupt occurs. As the placeholder addresses are unique, the host can easily calculate which interrupt type is pending. In the case of legacy syscalls, an internal wrapper is used to proxy these calls to the same handler that is used by the `SYSCALL` instruction, before returning cleanly via `IRETQ`.

## Memory Paging

As mentioned earlier, the emulator creates a child process, and all virtual memory within that process is mapped directly into the guest using the same address layout. A paging table is used to map virtual addresses to the corresponding physical pages.

Instead of mapping the entire address space of the process upfront, a fixed number of physical pages are allocated for the guest. The emulator contains a very basic memory manager, and pages are mapped "on demand". When a page fault occurs, the requested page will be paged in, and execution resumes. If all page "slots" are full, the oldest entry is swapped out to make room for the new one.

In addition to using a fixed number of currently-mapped pages, the emulator also uses a fixed-size page table. The size of the page table is determined by calculating the maximum possible number of tables (`PML4`, `PDPT`, `PD`, `PT`) for the amount of mapped page entries. This model results in a simple and consistent physical memory layout but comes at the cost of efficiency. In fact, the paging tables take up more space than the actual page entries. However, as the emulator functions well even with a small number of allocated pages, this level of overhead is not a major concern.

## Limitations

**Single-thread only**

The emulator currently only supports virtualizing a single thread. If the target executable creates additional threads, they will be executed natively. To support multiple threads, a pseudo-scheduler could be developed to handle this in the future.

The Windows parallel loader is disabled to ensure all module dependencies are loaded by a single thread.

**Software exceptions**

Virtualized software exceptions are not currently supported. If an exception occurs, the system will call the `KiUserExceptionDispatcher` function natively within the target process as usual.

**Safety issues**

There are several ways to "escape" the VM, such as simply creating a new process/thread, scheduling APC calls, etc. Windows GUI-related syscalls can also make nested calls directly back into user-mode from the kernel, which would currently bypass the hypervisor layer. For this reason, GUI executables such as `notepad.exe` are only partially virtualized when run under WinVisor at this time.

**Shared host memory**

As the WinVisor host DLL is injected into the target process, it exists within the same virtual address space as the target executable in the guest. This means the code running within the virtual CPU is able to directly access the memory within the host hypervisor module, and could potentially corrupt it.

**Non-executable guest memory**

While the virtual CPU is set up to support NX, all memory regions are currently mirrored into the guest with full RWX access.

## Further Reading

This project is described in further detail in the following article:
(add URL)

During development, I came across a similar project called [Simpleator](https://github.com/ionescu007/Simpleator) by Alex Ionescu. His project also utilizes the WHP API to emulate Windows x64 binaries, but is implemented in a very different way.
