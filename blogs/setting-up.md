---
title: Aya Rust tutorial Part Two - Setting up
date: "2024-05-09"
toc: false
tags: ebpf,rust,linux,networking
---
&copy; steve latif 

# Part Two: Setting up the Prerequisites


## Assumptions

All the examples will be run on Ubuntu Linux. On other distributions your mileage may vary


## First step: setup dependencies

Install packages 

    $ sudo apt install clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386  \
    graphviz  make gcc libssl-dev bc libelf-dev libcap-dev clang gcc-multilib  \
    libncurses5-dev git pkg-config libmnl-dev bison flex linux-tools-$(uname -r) \
	llvm

Verify that you have \`bpftool\` installed on your system

    $ sudo bpftool prog 

If there are problems installing it from a package, you can install it from source:

    $ git clone --recurse-submodules https://github.com/libbpf/bpftool.git
    $ cd bpftool/src
    $ make -j$(nproc)
    $ sudo ./bpftool prog

Install rust, following the instructions at <https://rustup.rs/>

    $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Once you have rust and cargo installed and in your path, install the following rust related tools:

    $ rustup udpate
    $ cargo install cargo-generate
    $ cargo install bpf-linker
    $ cargo install cargo-generate
    $ cargo install rustfmt
    $ cargo install bpf-linker

