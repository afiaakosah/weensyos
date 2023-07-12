#include "kernel.hh"
#include "k-apic.hh"
#include "k-vmiter.hh"
#include <atomic>

// kernel.cc
//
//    This is the kernel.


// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ...  : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

proc ptable[NPROC];             // array of process descriptors
                                // Note that `ptable[0]` is never used.
proc* current;                  // pointer to currently executing proc

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static std::atomic<unsigned long> ticks; // # timer interrupts so far


// Memory state
//    Information about physical page with address `pa` is stored in
//    `pages[pa / PAGESIZE]`. In the handout code, each `pages` entry
//    holds an `refcount` member, which is 0 for free pages.
//    You can change this as you see fit.

pageinfo pages[NPAGES];


[[noreturn]] void schedule();
[[noreturn]] void run(proc* p);
void exception(regstate* regs);
uintptr_t syscall(regstate* regs);
void memshow();


// kernel(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

static void process_setup(pid_t pid, const char* program_name);

void kernel(const char* command) {
    // Initialize hardware.
    init_hardware();
    log_printf("Starting WeensyOS\n");

    // Initialize timer interrupt.
    ticks = 1;
    init_timer(HZ);

    // Clear screen.
    console_clear();

    // (re-)Initialize the kernel page table.
    for (vmiter it(kernel_pagetable); it.va() < MEMSIZE_PHYSICAL; it += PAGESIZE) {
        // if (it.va() != 0) {
        //     it.map(it.va(), PTE_P | PTE_W | PTE_U);
        // } else {
        //     // nullptr is inaccessible even to the kernel
        //     it.map(it.va(), 0);
        // }

        if(it.va() < PROC_START_ADDR && it.va() != 0 && it.va() != CONSOLE_ADDR){
            it.map(it.va(), PTE_P | PTE_W);
        } else if (it.va() != 0)  { //?? 
            it.map(it.va(), PTE_P | PTE_W | PTE_U);
        } else {
            it.map(it.va(), 0);
        }

    }

    // Set up process descriptors.
    for (pid_t i = 0; i < NPROC; i++) {
        ptable[i].pid = i;
        ptable[i].state = P_FREE;
    }
    if (command && program_loader(command).present()) {
        process_setup(1, command);
    } else {
        process_setup(1, "allocator");
        process_setup(2, "allocator2");
        process_setup(3, "allocator3");
        process_setup(4, "allocator4");
    }

    // Switch to the first process using run().
    run(&ptable[1]);
}


// kalloc(sz)
//    Kernel memory allocator. Allocates `sz` contiguous bytes and
//    returns a pointer to the allocated memory (the physical address of
//    the newly allocated memory), or `nullptr` on failure.
//
//    The returned memory is initialized to 0xCC, which corresponds to
//    the x86 instruction `int3` (this may help you debug). You can
//    reset it to something more useful.
//
//    On WeensyOS, `kalloc` is a page-based allocator: if `sz > PAGESIZE`
//    the allocation fails; if `sz < PAGESIZE` it allocates a whole page
//    anyway.
//
//    The stencil code returns the next allocatable free page it can find,
//    but it never reuses pages or supports freeing memory (you'll have to
//    change this at some point).

// static uintptr_t next_alloc_pa;

void* kalloc(size_t sz) {
    if (sz > PAGESIZE) {
        return nullptr;
    }

    uintptr_t i = 0;
    while (i < MEMSIZE_PHYSICAL) {
        uintptr_t pa = i;
        i += PAGESIZE;

        if (allocatable_physical_address(pa) 
            && !pages[pa / PAGESIZE].used()) {
            pages[pa / PAGESIZE].refcount = 1;
            memset((void*) pa, 0xCC, PAGESIZE);
            return (void*) pa;
        }
    }
    return nullptr;
}


// kfree(kptr)
//    Frees `kptr`, which must have been previously returned by `kalloc`.
//    If `kptr == nullptr` does nothing.

void kfree(void* kptr) {
    if (kptr == nullptr) {
    return;
    }
    uintptr_t kptr_addr = (uintptr_t) kptr;
    pages[kptr_addr / PAGESIZE].refcount--;
}

// copy_mappings(x86_64_pagetable*, x86_64_pagetable*)
//    Copy all virtual memory mappings from `src` into `dst`
//    for addresses in the range [0, PROC_START_ADDR).
//    You may assume that `dst` starts out empty (has no mappings).

void copy_mappings(x86_64_pagetable* dst, x86_64_pagetable* src) {
    for (vmiter src_it(src, 0); src_it.va() < PROC_START_ADDR; src_it += PAGESIZE) {
        // This leaves all addresses above PROC_START_ADDR completely unmapped
        // ?? - how is it after Proc_start_addr?
        vmiter dst_it = vmiter(dst, src_it.va());
        dst_it.map(src_it.pa(), src_it.perm());
    }
}


// process_setup(pid, program_name)
//    Loads application program `program_name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.

void process_setup(pid_t pid, const char* program_name) {
    init_process(&ptable[pid], 0);

    // Allocate space for the new page table and clear it
    x86_64_pagetable* copied_pt_ptr = (x86_64_pagetable*) kalloc(PAGESIZE);
    memset(copied_pt_ptr, 0, PAGESIZE);

    // Initialize this process's page table (with perms) after PROC_START_ADDR 
    copy_mappings(copied_pt_ptr, kernel_pagetable);

    // Initialize `program_loader`.
    // The `program_loader` is an iterator that visits segments of executables.
    program_loader loader(program_name);

    // Using the loader, we're going to start loading segments of the program binary into memory
    // (recall that an executable has code/text segment, data segment, etc).

    // First, for each segment of the program, we allocate page(s) of memory.    
    for (loader.reset(); loader.present(); ++loader) {
        for (uintptr_t a = round_down(loader.va(), PAGESIZE);
                a < loader.va() + loader.size();
                a += PAGESIZE) {
            // `a` is the virtual address of the current segment's page.
            uintptr_t new_pa = (uintptr_t) kalloc(PAGESIZE);

            vmiter copy_vmiter = vmiter(copied_pt_ptr, a);
            if (loader.writable()) {
                copy_vmiter.map(new_pa, PTE_P | PTE_W | PTE_U);
            } else {
                copy_vmiter.map(new_pa, PTE_P | PTE_U);
            }
        }
    }

    ptable[pid].pagetable = copied_pt_ptr;

    // We now copy instructions and data into memory that we just allocated.
    for (loader.reset(); loader.present(); ++loader) {
        vmiter copy_vmiter = vmiter(copied_pt_ptr, loader.va());
        memset((void*) copy_vmiter.pa(), 0, loader.size());
        memcpy((void*) copy_vmiter.pa(), loader.data(), loader.data_size());
    }

    // Set %rip and mark the entry point of the code.
    ptable[pid].regs.reg_rip = loader.entry();

    // We also need to allocate a page for the stack.
    uintptr_t stack_addr = MEMSIZE_VIRTUAL - PAGESIZE;
    uintptr_t new_stack_pa = (uintptr_t) kalloc(PAGESIZE);
    vmiter copy_vmiter = vmiter(copied_pt_ptr, stack_addr);
    copy_vmiter.map(new_stack_pa, PTE_P | PTE_W | PTE_U);

    // Set %rsp to the start of the stack.
    ptable[pid].regs.reg_rsp = stack_addr + PAGESIZE;

    // Finally, mark the process as runnable.
    ptable[pid].state = P_RUNNABLE;
}



// exception(regs)
//    Exception handler (for interrupts, traps, and faults).
//    You should *not* have to edit this function.
//
//    The register values from exception time are stored in `regs`.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (see
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception(). This way, the process can be resumed right where
//    it left off before the exception. The pushed registers are popped and
//    restored before returning to the process (see k-exception.S).
//
//    Note that hardware interrupts are disabled when the kernel is running.

void exception(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: exception %d at rip %p\n",
                current->pid, regs->reg_intno, regs->reg_rip); */

    // Show the current cursor location and memory state (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if (regs->reg_intno != INT_PF || (regs->reg_errcode & PFERR_USER)) {
        memshow();
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER:
        ++ticks;
        lapicstate::get().ack();
        schedule();
        break;                  /* will not be reached */

    case INT_PF: {
        // Analyze faulting address and access type.
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PFERR_WRITE
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if (!(regs->reg_errcode & PFERR_USER)) {
            panic("Kernel page fault for %p (%s %s, rip=%p)!\n",
                  addr, operation, problem, regs->reg_rip);
        }
        console_printf(CPOS(24, 0), 0x0C00,
                       "Process %d page fault for %p (%s %s, rip=%p)!\n",
                       current->pid, addr, operation, problem, regs->reg_rip);
        current->state = P_BROKEN;
        break;
    }

    default:
        panic("Unexpected exception %d!\n", regs->reg_intno);

    }

    // Return to the current process (or run something else).
    if (current->state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}


// syscall(regs)
//    System call handler.
//
//    The register values from system call time are stored in `regs`.
//    The return value, if any, is returned to the user process in `%rax`.
//
//    Note that hardware interrupts are disabled when the kernel is running.

// Headers for helper functions used by syscall.
int syscall_page_alloc(uintptr_t addr);
pid_t syscall_fork();
void syscall_exit();

uintptr_t syscall(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: syscall %d at rip %p\n",
                  current->pid, regs->reg_rax, regs->reg_rip); */

    // Show the current cursor location and memory state (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    memshow();

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();

    // Actually handle the exception.
    switch (regs->reg_rax) {

    case SYSCALL_PANIC:
        panic(nullptr); // does not return

    case SYSCALL_GETPID:
        return current->pid;

    case SYSCALL_YIELD:
        current->regs.reg_rax = 0;
        schedule(); // does not return

    case SYSCALL_PAGE_ALLOC:
        return syscall_page_alloc(current->regs.reg_rdi);

    case SYSCALL_FORK:
        return syscall_fork();

    case SYSCALL_EXIT:
        syscall_exit();
        schedule(); // does not return

    default:
        panic("Unexpected system call %ld!\n", regs->reg_rax);

    }

    panic("Should not get here!\n");
}


// syscall_page_alloc(addr)
//    Helper function that handles the SYSCALL_PAGE_ALLOC system call.
//    This function implement the specification for `sys_page_alloc`
//    in `u-lib.hh` (but in the stencil code, it does not - you will
//    have to change this).
//    `Addr` should be page-aligned (i.e., a multiple of PAGESIZE == 4096),
//    >= PROC_START_ADDR, and < MEMSIZE_VIRTUAL.

int syscall_page_alloc(uintptr_t addr) {
    if (addr < PROC_START_ADDR || addr >= MEMSIZE_VIRTUAL || addr % PAGESIZE != 0) {
    return -1;
    }

    // allocate a page for the pa for now
    // ??
    void* new_pa = kalloc(PAGESIZE);
    if (!new_pa) {
        return -1;
    }

    memset(new_pa, 0, PAGESIZE);
    // x86_64_pagetable* new_pt = (x86_64_pagetable*) new_pa; // ??

    vmiter curr_pt_vmiter = vmiter(ptable[current->pid].pagetable, addr);
    int map_status = curr_pt_vmiter.try_map((uintptr_t) new_pa, PTE_P | PTE_W | PTE_U); //?? hwhy try map?
    if (map_status != 0) {
        kfree(new_pa);
        return -1;
    }
    return 0;

    memset((void*) addr, 0, PAGESIZE);
    return 0;
}

// copy_mappings_with_isolation(x86_64_pagetable*, x86_64_pagetable*)
//    Copy all virtual memory mappings from `src` into `dst`
//    for addresses in the range [0, MEMSIZE_VIRTUAL). Returns 0 if successful,
//    -1 if out of memory.
//    NOTE: Allocates new physical memory for user-accessible addresses in `src`.
//    NOTE: Shares read-only pages between processes rather than copying them
//    You may assume that `dst` starts out empty (has no mappings).
int copy_mappings_with_isolation(x86_64_pagetable* dst, x86_64_pagetable* src) {
    for (vmiter src_it(src, 0); src_it.va() < MEMSIZE_VIRTUAL; src_it += PAGESIZE) {
        vmiter dst_it = vmiter(dst, src_it.va());

        if (src_it.user() && src_it.va() != CONSOLE_ADDR) {

            if (src_it.writable()) {
                // allocate new physical page
                void* new_pa = kalloc(PAGESIZE);
                // if no kalloc-able memory left, return -1
                if (new_pa == nullptr) {
                    return -1;
                }

                // copy data from source's physical page,
                memcpy(new_pa, (void*) src_it.pa(), PAGESIZE);
                // map this new page in destination
                int map_status = dst_it.try_map((uintptr_t) new_pa, src_it.perm());
                if (map_status != 0) {
                    kfree(new_pa);
                    return -1;
                }

            } else {
                int map_status = dst_it.try_map(src_it.pa(), src_it.perm());
                if (map_status != 0) {
                    return -1;
                }
                // increment refcount to show that we're sharing read-only pages
                if (!src_it.writable() && (src_it.pa() / PAGESIZE) < NPAGES) {
                    pages[src_it.pa() / PAGESIZE].refcount++;
                }
            }

        } else {
            // directly copy over
            int map_status = dst_it.try_map(src_it.pa(), src_it.perm());
            if (map_status != 0) {
                return -1;
            }
        }
    }
    return 0;
}


void free_pt_memory(x86_64_pagetable* pt) {

    for (vmiter srcIt(pt, 0); srcIt.va() < MEMSIZE_VIRTUAL; srcIt += PAGESIZE) {
        if (srcIt.user() && srcIt.pa() != CONSOLE_ADDR) {
            kfree(srcIt.kptr());
        }
    }

    for (ptiter it(pt); it.active(); it.next()) {
        // frees user-accessible pages that are not at the console address
        kfree(it.kptr());
    }

    kfree(pt);
}


// syscall_fork()
//    Handles the SYSCALL_FORK system call. This function
//    implements the specification for `sys_fork` in `u-lib.hh`.
pid_t syscall_fork() {
    // set free_slot_id to a free process slot in ptable array
    pid_t free_slot_id;
    for (free_slot_id = 1; free_slot_id < NPROC; ++free_slot_id) {
        if (ptable[free_slot_id].state == P_FREE) {
            break;
        }
        // return -1; // wouldn't this work?
    }

    // if no free slots found, return -1 to signal an issue
    if (free_slot_id == NPROC) {
        return -1;
    }

    // set up PT for child proc
    ptable[free_slot_id].pid = free_slot_id;
    x86_64_pagetable* child_pt = (x86_64_pagetable*) kalloc(PAGESIZE);
    if (!child_pt) {
        return -1;
    }
    memset(child_pt, 0, PAGESIZE);

    // copy current->pagetable into the new process while allocating new physical 
    // memory for previously user-accessible addresses
    int copy_status = copy_mappings_with_isolation(child_pt, current->pagetable);
    if (copy_status == -1) {
        // clean up everything allocated so far
        free_pt_memory(child_pt);
        return -1;
    }

    ptable[free_slot_id].pagetable = child_pt;
    ptable[free_slot_id].regs = current->regs;
    // override parent's rax to be child PID
    current->regs.reg_rax = free_slot_id;
    // override child's rax to be 0
    ptable[free_slot_id].regs.reg_rax = 0;
    ptable[free_slot_id].state = P_RUNNABLE;

    return free_slot_id;

}

// syscall_exit()
//    Handles the SYSCALL_EXIT system call. This function
//    implements the specification for `sys_exit` in `u-lib.hh`.
void syscall_exit() {
    // free all of the process's memory
    free_pt_memory(current->pagetable);
    // mark process as free,
    current->state = P_FREE;    
}

// schedule
//    Picks the next process to run and then run it.
//    If there are no runnable processes, spins forever.
//    You should *not* have to edit this function.

void schedule() {
    pid_t pid = current->pid;
    for (unsigned spins = 1; true; ++spins) {
        pid = (pid + 1) % NPROC;
        if (ptable[pid].state == P_RUNNABLE) {
            run(&ptable[pid]);
        }

        // If Control-C was typed, exit the virtual machine.
        check_keyboard();

        // If spinning forever, show the memviewer.
        if (spins % (1 << 12) == 0) {
            memshow();
            log_printf("%u\n", spins);
        }
    }
}


// run(p)
//    Runs process `p`. This involves setting `current = p` and calling
//    `exception_return` to restore its page table and registers.
//    You should *not* have to edit this function.

void run(proc* p) {
    assert(p->state == P_RUNNABLE);
    current = p;

    // Check the process's current pagetable.
    check_pagetable(p->pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(p);

    // should never get here
    while (true) {
    }
}


// memshow()
//    Draws a picture of memory (physical and virtual) on the CGA console.
//    Switches to a new process's virtual memory map every 0.25 sec.
//    Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.
//    You should *not* have to edit this function.

void memshow() {
    static unsigned last_ticks = 0;
    static int showing = 0;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        showing = (showing + 1) % NPROC;
    }

    proc* p = nullptr;
    for (int search = 0; !p && search < NPROC; ++search) {
        if (ptable[showing].state != P_FREE
            && ptable[showing].pagetable) {
            p = &ptable[showing];
        } else {
            showing = (showing + 1) % NPROC;
        }
    }

    extern void console_memviewer(proc* vmp);
    console_memviewer(p);
}
