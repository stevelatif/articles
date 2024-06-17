---
layout: post
title: Aya Rust tutorial Part Five
subtitle: Part Five
tags: [ebpf, rust, linux]
---

&copy; steve latif 

# Aya Rust Tutorial part 5: Using Maps

Welcome to part 4. So far we have created a basic hello world program in Part [Four](https://medium.com/@stevelatif/aya-rust-tutorial-part-four-xdp-hello-world-c41abf76c353).
In this chapter we will start looking at how to pass data
between the kernel and user space using Maps.

# Overview: What is a Map and why do we need them ?

The eBPF verifier enforces a 512 byte limit per stack frame,
if you need to handle more data you can store data using
[maps](https://docs.kernel.org/bpf/maps.html)

- Maps are created on the kernel code
- Maps are accessible from  user space using a system call and a key
- Maps allow persistence across program invocations
- Maps offer different storage types

Maps in eBPF are a basic building block and we will be using them extensively
in the next sections. Our first example will build on the previous
example and will be a packet counter using an array.

Let's take a minute to look at the kernel code and
see the definitions there.
Maps are defined in [libbpf.h](https://elixir.bootlin.com/linux/latest/source/tools/lib/bpf/libbpf.c#L511) 

```c
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
```

The different map types:

- BPF_MAP_TYPE_ARRAY                
- BPF_MAP_TYPE_PERCPU_ARRAY         
- BPF_MAP_TYPE_PROG_ARRAY           
- BPF_MAP_TYPE_PERF_EVENT_ARRAY     
- BPF_MAP_TYPE_CGROUP_ARRAY         
- BPF_MAP_TYPE_CGROUP_STORAGE         
- BPF_MAP_TYPE_CGROUP_STORAGE       
- BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
- BPF_MAP_TYPE_HASH                 
- BPF_MAP_TYPE_PERCPU_HASH          
- BPF_MAP_TYPE_LRU_HASH             
- BPF_MAP_TYPE_LRU_PERCPU_HASH      
- BPF_MAP_TYPE_LPM_TRIE             
- BPF_MAP_TYPE_STACK_TRACE          
- BPF_MAP_TYPE_ARRAY_OF_MAPS        
- BPF_MAP_TYPE_HASH_OF_MAPS         
- BPF_MAP_TYPE_INODE_STORAGE        
- BPF_MAP_TYPE_TASK_STORAGE         
- BPF_MAP_TYPE_DEVMAP               
- BPF_MAP_TYPE_DEVMAP_HASH          
- BPF_MAP_TYPE_SK_STORAGE           
- BPF_MAP_TYPE_CPUMAP               
- BPF_MAP_TYPE_XSKMAP               
- BPF_MAP_TYPE_SOCKMAP              
- BPF_MAP_TYPE_SOCKHASH             
- BPF_MAP_TYPE_REUSEPORT_SOCKARRAY  
- BPF_MAP_TYPE_QUEUE                
- BPF_MAP_TYPE_STACK                
- BPF_MAP_TYPE_STRUCT_OPS           
- BPF_MAP_TYPE_RINGBUF              
- BPF_MAP_TYPE_BLOOM_FILTER         
- BPF_MAP_TYPE_USER_RINGBUF         
- BPF_MAP_TYPE_ARENA                

are defined in [map](https://elixir.bootlin.com/linux/latest/source/include/linux/bpf_types.h#L87)

The corresponding aya definitions are documented [here](https://docs.aya-rs.dev/aya_ebpf/maps/) 
for the kernel side. 
The corresponding user space entries are [here](https://docs.aya-rs.dev/aya/maps/)

Our initial example will be a simple per CPU packet counter that will print out 
from user space the number of packets arriving at an interface 

In the C API helper functions are used on both the kernel and user space side. 
The helpers have the same names on both sides.
The kernel side helper functions have access to a pointer to the map and key.

On the user space side the helper functions use a syscall and file descriptor. 

In Aya on the kernel [side](https://docs.aya-rs.dev/aya_ebpf/maps/)

- array::Array
- bloom_filter::BloomFilter
- hash_map::HashMap
- hash_map::LruHashMap
- hash_map::LruPerCpuHashMap
- hash_map::PerCpuHashMap
- lpm_trie::LpmTrie
- per_cpu_array::PerCpuArray
- perf::PerfEventArray
- perf::PerfEventByteArray
- program_array::ProgramArray
- queue::Queue
- ring_buf::RingBuf
- sock_hash::SockHash
- sock_map::SockMap
- stack::Stack
- stack_trace::StackTrace
- xdp::CpuMap
- xdp::DevMap
- xdp::DevMapHash
- xdp::XskMap

While on the user space [side](https://docs.aya-rs.dev/aya_ebpf/maps/)
We have the same function list.

As before generate the code from the template using the command
```shell
 cargo generate https://github.com/aya-rs/aya-template
```

I called the project `xdp-map-counter`

Lets set up the packet counter, on the eBPF side:

```rust
#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action,
	       macros::{xdp, map},
	       programs::XdpContext,
	       maps::PerCpuArray,
};

const CPU_CORES: u32 = 16;

#[map(name="PKT_CNT_ARRAY")]
static mut PACKET_COUNTER: PERCPU<u32> = PerCpuArray::with_max_entries(CPU_CORES , 0);

#[xdp]
pub fn xdp_map_counter(_ctx: XdpContext) -> u32 {
    match try_xdp_map_counter() {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] 
fn try_xdp_map_counter() -> Result<u32, ()> {
    unsafe {
	let counter = PACKET_COUNTER
            .get_ptr_mut(0)
     	    .ok_or(())? ;
	*counter += 1;
    }
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

```

The map will be created on the eBPF side. We will use a PerCpuArray in
this first example. Arrays are simple to work with. With the PerCpuArray
each CPU sees its own instance of the map, this means that it avoids
lock contention and is therefore the most performant way to get 
readings from eBPF to user land. The downside is that updating the 
values from user space can't be done safely.

The size of array must be known at build time so we set a constant with an 
upper bound on the number of cores on the system
`const CPU_CORES: u32 = 16`

Then we can define a PerCpuArray with `CPU_CORES` entries initialized to 0.

```rust
#[map(name="PKT_CNT_ARRAY")]
static mut PACKET_COUNTER: PerCpuArray<u32> = PerCpuArray::with_max_entries(CPU_CORES, 0);

```

The main work is in the `try_xdp_counter` function.
We get a pointer to the map and then increment the value

```rust
    unsafe {
	let counter = PACKET_COUNTER
            .get_ptr_mut(0)
     	    .ok_or(())? ;
	*counter += 1;
    }

```

Note that the call to  `ok_or()` is required, failing to have the check 
here will fail the eBPF verifier. 


The packet is then passed on to the networking stack.

```rust
    Ok(xdp_action::XDP_PASS)
```

The code on the user space side:

```rust
use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya::maps::PerCpuValues;
use aya::maps::PerCpuArray;
use aya_log::BpfLogger;
use clap::Parser;
use log::{warn, debug};
use aya::util::nr_cpus;
//use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-map-counter"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-map-counter"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("xdp_map_counter").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let array = PerCpuArray::try_from(bpf.map_mut("PKT_CNT_ARRAY").unwrap())?;

    loop {
	let cc: PerCpuValues<u32> = array.get(&0, 0)?;
	let mut total : u32 =  0;
	//println!("{:?} packets",  cc);
	for ii in 1..nr_cpus().expect("failed to get number of cpus") {
	    print!("{} ", cc[ii]);
	    total += cc[ii];
	}
	println!("total: {} ", total);
	std::thread::sleep(std::time::Duration::from_secs(1));
    }
    //signal::ctrl_c().await?;    
}

```

The array reference is created on the user space side here with name 
'PKT_CNT_ARRAY'	

```rust
    let array = PerCpuArray::try_from(bpf.map_mut("PKT_CNT_ARRAY").unwrap())?;
```

and must match the name declared in the eBPF code 
```rust
#[map(name="PKT_CNT_ARRAY")]
static mut COUNTER: PerCpuArray<u32> = PerCpuArray::with_max_entries(CPU_CORES , 0);
```

Most of the rest of the code is boilerplate except for the loop at the end which checks every 
second for the results from the kernel eBPF code and then prints out the stats.

```rust
 loop {
	let cc: PerCpuValues<u32> = array.get(&0, 0)?;
	let mut total : u32 =  0;
	for ii in 1..nr_cpus().expect("failed to get number of cpus") {
	    print!("{} ", cc[ii]);
	    total += cc[ii];
	}
	println!("total: {} ", total);
	std::thread::sleep(std::time::Duration::from_secs(1));
    }
   
```

## Testing

As we did before we can run it over the loopback interface.
Build as before

```shell
cargo xtask build-ebpf
cargo build
```

Then run
```shell
cargo xtask run -- -i lo
```

In another terminal ping the loopback interface
```shell

ping 127.0.0.1
```

In the terminal where you are running the `cargo run` command you should see 
```shell
0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 total: 0 
0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 total: 0 
0 0 2 0 0 0 0 0 0 0 0 0 0 0 0 total: 2 
0 0 4 0 0 0 0 0 0 0 0 0 0 0 0 total: 4 
0 0 6 0 0 0 0 0 0 0 0 0 0 0 0 total: 6 
0 0 8 0 0 0 0 0 0 0 0 0 0 0 0 total: 8 
0 0 10 0 0 0 0 0 0 0 0 0 0 0 0 total: 10 
```

We can see packets arriving and being processed on one core. 
To run  a more stressful test, replace the ping with the 
following ssh command:

```shell
 ssh 127.0.0.1 cat /dev/zero
```

You should see something like:

```shell
 0 0 0 0 0 0 0 0 0 0 0 0 0 0 total: 0 
0 7 6 2 0 0 0 0 0 0 0 5 0 0 0 total: 20 
0 7 6 2 0 0 0 0 0 0 0 6 0 0 0 total: 21 
0 7 6 2 0 0 0 0 0 0 0 6 0 0 0 total: 21 
0 7 6 2 0 0 0 0 0 0 0 6 0 0 0 total: 21 
0 7 6 2 0 0 0 0 0 0 0 6 0 0 0 total: 21 
0 48 12 2 0 16 0 0 0 0 0 8 0 702 0 total: 788 
0 48 133 12 0 527 0 0 0 5 0 8 94 1978 558 total: 3363 
0 48 133 243 0 527 0 17 0 5 0 8 94 1978 3179 total: 6232 
0 48 133 243 0 645 0 144 64 23 0 8 94 1978 5800 total: 9180 
0 48 133 243 0 733 0 201 64 203 2 8 94 1978 8406 total: 12113 
0 48 133 243 0 903 0 333 64 228 2 8 94 1978 11027 total: 15061 
0 48 133 243 0 1447 0 548 64 237 2 8 94 1978 13136 total: 17938 
0 368 133 243 0 3908 0 548 64 237 2 8 94 1978 13136 total: 20719 
0 595 133 416 0 6529 0 548 64 237 2 8 94 1978 13136 total: 23740 
0 683 133 674 0 9294 0 548 64 237 2 8 94 1978 13136 total: 26851 
0 854 133 927 0 11544 0 548 64 296 2 440 94 1978 13136 total: 30016 
...
```

Run it for a few iterations before Ctrl-C ing it.

As before lets take a minute to look at the eBPF byte code which corresponds to 
the code in the XDP section of `xdp-map-counter/xdp-map-counter-ebpf/src/main.rs`

```rust
fn try_xdp_map_counter() -> Result<u32, ()> {
    unsafe {
	let counter = COUNTER
            .get_ptr_mut(0)
     	    .ok_or(())? ;
	*counter += 1;
    }
    Ok(xdp_action::XDP_PASS)
}
```

Using `llvm-objdump` as before

```shell
$ llvm-obj dump --section=xdp  -S target/bpfel-unknown-none/debug/xdp-map-counter
```

```asm
target/bpfel-unknown-none/debug/xdp-map-counter:	file format elf64-bpf

Disassembly of section xdp:

0000000000000000 <xdp_map_counter>:
       0:	b7 06 00 00 00 00 00 00	r6 = 0
       1:	63 6a fc ff 00 00 00 00	*(u32 *)(r10 - 4) = r6
       2:	bf a2 00 00 00 00 00 00	r2 = r10
       3:	07 02 00 00 fc ff ff ff	r2 += -4
       4:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0 ll
       6:	85 00 00 00 01 00 00 00	call 1
       7:	15 00 04 00 00 00 00 00	if r0 == 0 goto +4 <LBB0_2>
       8:	61 01 00 00 00 00 00 00	r1 = *(u32 *)(r0 + 0)
       9:	07 01 00 00 01 00 00 00	r1 += 1
      10:	63 10 00 00 00 00 00 00	*(u32 *)(r0 + 0) = r1
      11:	b7 06 00 00 02 00 00 00	r6 = 2

0000000000000060 <LBB0_2>:
      12:	bf 60 00 00 00 00 00 00	r0 = r6
      13:	95 00 00 00 00 00 00 00	exit

```

We see that byte code maps closely to the rust code.
After setting up parameters in the first 4 lines, in line 6 we
have a `call 1` that is a system call to the bpf helper 
`map_lookup_elem` 
That value gets assigned to r1 where it is incremented on
line 9
and is then assigned to a location in  memory.

