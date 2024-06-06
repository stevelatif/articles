---
title: Aya Rust tutorial Part Four XDP Hello World
date: "2024-05-09"
toc: false
tags: ebpf,rust,linux,networking
---
&copy; steve latif 

# Aya Rust Tutorial Part 4: XDP Hello World

Welcome to part 4. So far we have installed the prerequisits in part 2,
built eBPF code that loads into the kernel and passes the
verifier. Let's continue on by building another XDP
program that will print a message everytime it receives a packet
on an interface. As in part 3 we will use the loopback interface.
This will show how to print a message from the kernel. This is ananlogous
to using 'bpf_printk' in the BPF programs bult in the C language
This will involve only a few more lines of code and 
will follow the same build and deployment process in the previous chapter.


# Generating the code

As we did in part 3 
generate the code using `cargo generate`
At the prompt select hello-world as the project name

Using the template, generate the code in directory \`hello-world\`, select the xdp option.

    $ cargo generate https://github.com/aya-rs/aya-template  
    ⚠️   Favorite `https://github.com/aya-rs/aya-template` not found in config, using it as a git repository: https://github.com/aya-rs/aya-template
    🤷   Project Name: hello-world
    🔧   Destination: /home/steve/articles/learning_ebpf_with_rust/xdp-tutorial/basic01-hello-world/hello-world ...
    🔧   project-name: hello-world ...
    🔧   Generating template ...
    ? 🤷   Which type of eBPF program? ›
      cgroup_skb
      cgroup_sockopt
      cgroup_sysctl
      classifier
      fentry
      fexit
      kprobe
      kretprobe
      lsm
      perf_event
      raw_tracepoint
      sk_msg
      sock_ops
      socket_filter
      tp_btf
      tracepoint
      uprobe
      uretprobe
    ❯ xdp


Modify the generated code in the file `hello-world/hello-world-ebpf/src/main.rs` 
so that it looks like:

	#![no_std]
	#![no_main]

	use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
	use aya_ebpf::bpf_printk;

	#[xdp]
	pub fn hello_world(_ctx: XdpContext) -> u32 {
		unsafe {
			bpf_printk!(b"packet  received!");
		}
    xdp_action::XDP_PASS
	}

This code uses the unsafe macro [bpf_printk](https://docs.rs/aya-ebpf/latest/aya_ebpf/macro.bpf_printk.html) 
to print out a message everytime a packet is received on the interface. 
It returns \`XDP\_PASS\`


## Compile the code

    cargo xtask build-ebpf
    cargo build 


## Looking into the BPF-ELF object

As we did in the previous section, lets look at the generated eBPF bytecode

	$ llvm-readelf --sections target/bpfel-unknown-none/debug/hello-world
	There are 7 section headers, starting at offset 0x2e0:

	Section Headers:
		[Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
		[ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
		[ 1] .strtab           STRTAB          0000000000000000 000238 0000a2 00      0   0  1
		[ 2] .text             PROGBITS        0000000000000000 000040 000098 00  AX  0   0  8
		[ 3] xdp               PROGBITS        0000000000000000 0000d8 000030 00  AX  0   0  8
		[ 4] .relxdp           REL             0000000000000000 000228 000010 10   I  6   3  8
		[ 5] .rodata           PROGBITS        0000000000000000 000108 000013 00   A  0   0  1
		[ 6] .symtab           SYMTAB          0000000000000000 000120 000108 18      1   8  8
	Key to Flags:
		W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
		L (link order), O (extra OS processing required), G (group), T (TLS),
		C (compressed), x (unknown), o (OS specific), E (exclude),
		R (retain), p (processor specific)

As before we have an xdp section, lets disassemble that:

	$ llvm-objdump --no-show-raw-insn --section=xdp  -S target/bpfel-unknown-none/debug/hello-world

	target/bpfel-unknown-none/debug/hello-world:    file format elf64-bpf

	Disassembly of section xdp:

	0000000000000000 <hello_world>:
       0:       r1 = 0 ll
       2:       r2 = 19
       3:       call 6
       4:       r0 = 2
       5:       exit

Recall that the registers for eBPF:
- R0: Stores a return value of a function, and exit value for an eBPF program
- R1 - R5: Stores function arguments
- R6 - R9: For general purpose usage
- R10: Stores an address for stack frame

line 0 zeroes out the r1 register
line 2 sets r2 to 19 - the length of the output string
line 3 makes a system call, the mysterious 6 is the index of 
bpf_helpers found in [bpf.h](https://elixir.bootlin.com/linux/v5.3.7/source/include/uapi/linux/bpf.h#L2724)
line 4 sets the exit value to 2 which corresponds to XDP_PASS

To run this let's use cargo
	$ cargo xtask build-ebpf
	$ cargo build
	$ cargo xtask run -- i lo
	
To see output, open another terminal enable tracing:

	echo 1 | sudo tee /sys/kernel/debug/tracing/tracing_on

Then to see output
	
	sudo cat /sys/kernel/debug/tracing/trace_pipe

From another terminal, ping the loopback interface 

	ping 127.0.0.1
	
You should see output being logged in the terminal where you ran the `trace_pipe` command

	$ sudo cat /sys/kernel/debug/tracing/trace_pipe
	 ping-75348   [000] ..s21 47214.233803: bpf_trace_printk: packet  received!
	 ping-75348   [000] ..s21 47214.233815: bpf_trace_printk: packet  received!
	 ping-75348   [007] ..s21 47215.236704: bpf_trace_printk: packet  received!
	 ping-75348   [007] ..s21 47215.236737: bpf_trace_printk: packet  received!




# Summary

One small step from the previous version to 

-   print out a message when a packet is received

