---
title: Aya Rust tutorial Part Four XDP Hello World
date: "2024-05-09"
toc: false
tags: ebpf,rust,linux,networking
---
&copy; steve latif 

# Aya Rust Tutorial Part 4: XDP Hello World

Welcome to part 4. So far we have installed the prerequisite in part 2,
built eBPF code that loads into the kernel and passes the
verifier. Let's continue on by building another XDP
program that will print a message every time it receives a packet
on an interface. As in part 3 we will use the loopback interface.
This will show how to print a message from the kernel. This is analogous
to using 'bpf_printk' in the eBPF programs built in the C language
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
to print out a message every time a packet is received on the interface. 
It returns \`XDP\_PASS\`
bpf_printk is a useful tool for debugging but it is globally shared in the kernel 
so other programs using it may disrupt its output

## Compile the code

    cargo xtask build-ebpf
    cargo build 


## Looking into the BPF-ELF object

As we did in the previous section, lets look at the generated eBPF byte code

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

Let's return to the previous step where we generated the code. If we leave the generated 
code and don't change it:

	#![no_std]
	#![no_main]

	use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
	use aya_log_ebpf::info;

	#[xdp]
	pub fn hello_world(ctx: XdpContext) -> u32 {
		match try_hello_world(ctx) {
			Ok(ret) => ret,
			Err(_) => xdp_action::XDP_ABORTED,
		}
	}

	fn try_hello_world(ctx: XdpContext) -> Result<u32, u32> {
		info!(&ctx, "received a packet");
		Ok(xdp_action::XDP_PASS)
	}

	#[panic_handler]
	fn panic(_info: &core::panic::PanicInfo) -> ! {
		unsafe { core::hint::unreachable_unchecked() }
	}

Leaving it as it is and building and running it:

	cargo xtask build-ebpf
	cargo build
	RUST_LOG=info cargo xtask run -- -i lo
	
Then running ping in another terminal:

	ping 127.0.0.1 
	
You should see this output in the window where you ran `cargo xtask run`

	[2024-06-08T04:24:17Z INFO  hello_world] Waiting for Ctrl-C...
	[2024-06-08T04:24:21Z INFO  hello_world] received a packet
	[2024-06-08T04:24:21Z INFO  hello_world] received a packet
	[2024-06-08T04:24:22Z INFO  hello_world] received a packet
	...
	
This programs functions in the same way as the first one, but 
there are significant differences in the code. 

It looks more like idiomatic rust with only one unsafe block in 
the panic handler. 

However looking at a dump of the byte code:

	$ llvm-objdump --section=xdp  -S target/bpfel-unknown-none/debug/hello-world

target/bpfel-unknown-none/debug/hello-world:	file format elf64-bpf

Disassembly of section xdp:

	0000000000000000 <hello_world>:
       0:	r6 = r1
       1:	r7 = 0
       2:	*(u32 *)(r10 - 4) = r7
       3:	r2 = r10
       4:	r2 += -4
       5:	r1 = 0 ll
       7:	call 1
       8:	if r0 == 0 goto +166 <LBB0_2>
       9:	*(u8 *)(r0 + 2) = r7
      10:	r2 = 11
      11:	*(u8 *)(r0 + 1) = r2
      12:	r1 = 1
      13:	*(u8 *)(r0 + 0) = r1
      14:	r3 = r0
      15:	r3 += 3
      16:	r4 = 0 ll
      18:	r5 = *(u8 *)(r4 + 0)
      19:	*(u8 *)(r3 + 0) = r5
      20:	r5 = *(u8 *)(r4 + 1)
      21:	*(u8 *)(r3 + 1) = r5
      22:	r5 = *(u8 *)(r4 + 2)
      23:	*(u8 *)(r3 + 2) = r5
      24:	r5 = *(u8 *)(r4 + 3)
      25:	*(u8 *)(r3 + 3) = r5
      26:	r5 = *(u8 *)(r4 + 4)
      27:	*(u8 *)(r3 + 4) = r5
      28:	r5 = *(u8 *)(r4 + 5)
      29:	*(u8 *)(r3 + 5) = r5
      30:	r5 = *(u8 *)(r4 + 6)
      31:	*(u8 *)(r3 + 6) = r5
      32:	r5 = *(u8 *)(r4 + 7)
      33:	*(u8 *)(r3 + 7) = r5
      34:	r5 = *(u8 *)(r4 + 8)
      35:	*(u8 *)(r3 + 8) = r5
      36:	r5 = *(u8 *)(r4 + 9)
      37:	*(u8 *)(r3 + 9) = r5
      38:	r5 = *(u8 *)(r4 + 10)
      39:	*(u8 *)(r3 + 10) = r5
      40:	r3 = 3
      41:	*(u8 *)(r0 + 18) = r3
      42:	*(u8 *)(r0 + 17) = r3
      43:	r3 = 2
      44:	*(u8 *)(r0 + 14) = r3
      45:	*(u8 *)(r0 + 20) = r7
      46:	*(u8 *)(r0 + 19) = r2
      47:	*(u8 *)(r0 + 16) = r7
      48:	*(u8 *)(r0 + 15) = r1
      49:	r3 = r0
      50:	r3 += 21
      51:	r5 = *(u8 *)(r4 + 0)
      52:	*(u8 *)(r3 + 0) = r5
      53:	r5 = *(u8 *)(r4 + 1)
      54:	*(u8 *)(r3 + 1) = r5
      55:	r5 = *(u8 *)(r4 + 2)
      56:	*(u8 *)(r3 + 2) = r5
      57:	r5 = *(u8 *)(r4 + 3)
      58:	*(u8 *)(r3 + 3) = r5
      59:	r5 = *(u8 *)(r4 + 4)
      60:	*(u8 *)(r3 + 4) = r5
      61:	r5 = *(u8 *)(r4 + 5)
      62:	*(u8 *)(r3 + 5) = r5
      63:	r5 = *(u8 *)(r4 + 6)
      64:	*(u8 *)(r3 + 6) = r5
      65:	r5 = *(u8 *)(r4 + 7)
      66:	*(u8 *)(r3 + 7) = r5
      67:	r5 = *(u8 *)(r4 + 8)
      68:	*(u8 *)(r3 + 8) = r5
      69:	r5 = *(u8 *)(r4 + 9)
      70:	*(u8 *)(r3 + 9) = r5
      71:	r5 = *(u8 *)(r4 + 10)
      72:	*(u8 *)(r3 + 10) = r5
      73:	*(u8 *)(r0 + 33) = r2
      74:	*(u8 *)(r0 + 34) = r7
      75:	r2 = 4
      76:	*(u8 *)(r0 + 32) = r2
      77:	r3 = r0
      78:	r3 += 35
      79:	r4 = 11 ll
      81:	r5 = *(u8 *)(r4 + 0)
      82:	*(u8 *)(r3 + 0) = r5
      83:	r5 = *(u8 *)(r4 + 1)
      84:	*(u8 *)(r3 + 1) = r5
      85:	r5 = *(u8 *)(r4 + 2)
      86:	*(u8 *)(r3 + 2) = r5
      87:	r5 = *(u8 *)(r4 + 3)
      88:	*(u8 *)(r3 + 3) = r5
      89:	r5 = *(u8 *)(r4 + 4)
      90:	*(u8 *)(r3 + 4) = r5
      91:	r5 = *(u8 *)(r4 + 5)
      92:	*(u8 *)(r3 + 5) = r5
      93:	r5 = *(u8 *)(r4 + 6)
      94:	*(u8 *)(r3 + 6) = r5
      95:	r5 = *(u8 *)(r4 + 7)
      96:	*(u8 *)(r3 + 7) = r5
      97:	r5 = *(u8 *)(r4 + 8)
      98:	*(u8 *)(r3 + 8) = r5
      99:	r5 = *(u8 *)(r4 + 9)
     100:	*(u8 *)(r3 + 9) = r5
     101:	r5 = *(u8 *)(r4 + 10)
     102:	*(u8 *)(r3 + 10) = r5
     103:	*(u8 *)(r0 + 56) = r1
     104:	r1 = 8
     105:	*(u8 *)(r0 + 54) = r1
     106:	r1 = 16
     107:	*(u8 *)(r0 + 49) = r1
     108:	*(u8 *)(r0 + 66) = r7
     109:	*(u8 *)(r0 + 63) = r7
     110:	*(u8 *)(r0 + 62) = r7
     111:	*(u8 *)(r0 + 61) = r7
     112:	*(u8 *)(r0 + 60) = r7
     113:	*(u8 *)(r0 + 59) = r7
     114:	*(u8 *)(r0 + 58) = r7
     115:	*(u8 *)(r0 + 57) = r7
     116:	*(u8 *)(r0 + 55) = r7
     117:	*(u8 *)(r0 + 52) = r7
     118:	*(u8 *)(r0 + 51) = r7
     119:	*(u8 *)(r0 + 50) = r7
     120:	*(u8 *)(r0 + 48) = r7
     121:	*(u8 *)(r0 + 47) = r2
     122:	r1 = 17
     123:	*(u8 *)(r0 + 65) = r1
     124:	*(u8 *)(r0 + 64) = r1
     125:	r1 = 6
     126:	*(u8 *)(r0 + 53) = r1
     127:	r1 = 5
     128:	*(u8 *)(r0 + 46) = r1
     129:	r1 = r0
     130:	r1 += 67
     131:	r2 = 22 ll
     133:	r3 = *(u8 *)(r2 + 0)
     134:	*(u8 *)(r1 + 0) = r3
     135:	r3 = *(u8 *)(r2 + 1)
     136:	*(u8 *)(r1 + 1) = r3
     137:	r3 = *(u8 *)(r2 + 2)
     138:	*(u8 *)(r1 + 2) = r3
     139:	r3 = *(u8 *)(r2 + 3)
     140:	*(u8 *)(r1 + 3) = r3
     141:	r3 = *(u8 *)(r2 + 4)
     142:	*(u8 *)(r1 + 4) = r3
     143:	r3 = *(u8 *)(r2 + 5)
     144:	*(u8 *)(r1 + 5) = r3
     145:	r3 = *(u8 *)(r2 + 6)
     146:	*(u8 *)(r1 + 6) = r3
     147:	r3 = *(u8 *)(r2 + 7)
     148:	*(u8 *)(r1 + 7) = r3
     149:	r3 = *(u8 *)(r2 + 8)
     150:	*(u8 *)(r1 + 8) = r3
     151:	r3 = *(u8 *)(r2 + 9)
     152:	*(u8 *)(r1 + 9) = r3
     153:	r3 = *(u8 *)(r2 + 10)
     154:	*(u8 *)(r1 + 10) = r3
     155:	r3 = *(u8 *)(r2 + 11)
     156:	*(u8 *)(r1 + 11) = r3
     157:	r3 = *(u8 *)(r2 + 12)
     158:	*(u8 *)(r1 + 12) = r3
     159:	r3 = *(u8 *)(r2 + 13)
     160:	*(u8 *)(r1 + 13) = r3
     161:	r3 = *(u8 *)(r2 + 14)
     162:	*(u8 *)(r1 + 14) = r3
     163:	r3 = *(u8 *)(r2 + 15)
     164:	*(u8 *)(r1 + 15) = r3
     165:	r3 = *(u8 *)(r2 + 16)
     166:	*(u8 *)(r1 + 16) = r3
     167:	r1 = r6
     168:	r2 = 0 ll
     170:	r3 = 4294967295 ll
     172:	r4 = r0
     173:	r5 = 84
     174:	call 25

	0000000000000578 <LBB0_2>:
     175:	r0 = 2
     176:	exit

So there's a lot here, we will defer a full explanation till later, note that there are now 
two system calls on line 7 and line 174: 

       7:	call 1	
	   ...
     174:   call 25
	 
`call 1` corresponds to `map_lookup_elem` in [bpf.h](https://elixir.bootlin.com/linux/v5.3.7/source/include/uapi/linux/bpf.h#L2719)
`call 25` corresponding to ``perf_event_output` in [bpf.h](https://elixir.bootlin.com/linux/v5.3.7/source/include/uapi/linux/bpf.h#L2743)

Much of the rest of the byte code is setting up the stack to pass arguments. 

# Summary

- Seen how to set up and deploy a basic hello world program 
- print out a message when a packet is received

