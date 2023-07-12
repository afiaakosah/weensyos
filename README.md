WeensyOS
====================

## Design Overview:
An OS kernel that implements virtual memory architecture and a few important system calls for a small operating system. The WeensyOS supports 3MB of virtual memory on top of 2MB of physical memory.

Quickstart: `make run` will run the OS using the [QEMU](https://qemu.org/)
machine emulator.

Make targets
------------

Use `make run` to run the OS in a separate QEMU window. Close the QEMU
window, or type `q` inside it, to exit the OS.

Use `make run-console` to run the OS in the console window.

WeensyOS creates a debug log in `log.txt`. Run `make LOG=stdio run` to
redirect the debug log to the standard output, or `make
LOG=file:FILENAME run` to redirect it to `FILENAME`.

Run `make D=1 run` to ask QEMU to print verbose information about interrupts
and CPU resets to the standard error. This setting will also cause QEMU to
quit after encountering a [triple fault](https://en.wikipedia.org/wiki/
Triple_fault) (normally it will reboot).
Finally, run `make clean` to clean up your directory.

Building
--------

**Linux:** WeensyOS should build natively on a Linux machine or
virtual machine. `qemu` packages are required to run WeensyOS; on
Ubuntu, `sudo apt install qemu qemu-system-x86` should work. A recent
compiler is required, GCC 7 or GCC 8 if possible. Malte uses [Ubuntu
18.04](https://www.ubuntu.com/desktop/1804), on which GCC 7 is the
default. You can use [Clang](https://clang.llvm.org/), but only
version 5 or later.

**Mac OS X:** WeensyOS can build on Mac OS X after some tools are installed.

1. Install [Homebrew](https://brew.sh/).
2. Install Homebrew’s new GCC package: `brew install gcc`
3. Install Homebrew’s QEMU: `brew install qemu`
4. Tap [Sergio Benitez’s collection of cross-compilers](https://github.com/SergioBenitez/homebrew-osxct): `brew tap SergioBenitez/osxct`
5. Install the `x86_64-unknown-linux-gnu` cross-compiler toolchain: `brew install x86_64-unknown-linux-gnu`
6. Edit the file `config.mk` in your WeensyOS directory to contain this:

    ```make
CCPREFIX=x86_64-unknown-linux-gnu-
HOSTCC=gcc-8
HOSTCXX=g++-8 

## Collaborators:
Swetabh Changakoti
