---
layout: post
title: Simple Firewall with Rust and AA
subtitle: Firewall
tags: [ebpf, rust, linux, networking]
---

# Other Parts in this Series
- [Part 1 Introduction](https://medium.com/@stevelatif/aya-rust-tutorial-part-5-using-maps-4d26c4a2fff8)
- [Part 2 Setting Up](https://medium.com/@stevelatif/aya-rust-tutorial-part-two-setting-up-33b1e489cb93)
- [Part 3 XDP Pass](https://medium.com/@stevelatif/aya-rust-tutorial-part-three-xdp-pass-c9b8e6e4baac)
- [Part 4 XDP Hello World](https://medium.com/@stevelatif/aya-rust-tutorial-part-four-xdp-hello-world-c41abf76c353)
- [Part 5 XDP Using Maps](https://medium.com/@stevelatif/aya-rust-tutorial-part-5-using-maps-4d26c4a2fff8)

# Part 6 Creating a Simple Firewall
Welcome to Part 6. In this chapter we will extend the work we did in part 5
where we looked at a simple PerCpuArray map to count packets.

Using eBPF we can create a simple firewall/router. With a small amount of code we can 
drop or redirect packets based on the source and destination addresses. 
We will implement this in several stages using a hashmap to store the 
configuration. 
The initial version will load the IP addresses from user space and to the eBPF kernel code,
and with each iteration we can add more functionality.

As before, generate the code 
using `
```shell
cargo generate https://github.com/aya-rs/aya-template
```

I called the project `firewall-001`

# Modify the generated source code

Modify ebpf firewall-001-ebpf/Cargo.toml to include a dependency 
for the network-types crate:

```cargo
[dependencies]
aya-ebpf = "0.1.0"
aya-log-ebpf = "0.1.0"
firewall-001-common = { path = "../firewall-001-common" }
network-types = "0.0.5"
```

Then modify the ebpf code in `firewall-001-ebpf/src/main.rs`
so we can add HashMap map 

In the eBPF code `firewall-001-ebpf/src/main.rs`
the header section should look like this:

```rust
    use aya_ebpf::{bindings::xdp_action,
    	       macros::{xdp, 
    	       map }, // <---- added map macro
    	       programs::XdpContext,
    	       maps::HashMap // <--- added hashmaps
    	       };
    use aya_log_ebpf::info;
    use core::mem;    // <--- added memory crate
    
    use network_types::{ // Added
        eth::{EthHdr, EtherType}, 
        ip::{IpProto, Ipv4Hdr},
        tcp::TcpHdr,
        udp::UdpHdr,
    };
```

Add the map definition, as in Part 5 we define the map in the ebpf code in 
`firewall-001/firewall-001-ebpf/src/main.rs`

```rust
    #[map(name = "SRC_IP_FILTER")]
    static mut SRC_IP_FILTER: HashMap<u32, u8> =
        HashMap::<u32, u8>::with_max_entries(1024, 0);
```

As we are working with the eBPF subsystem in the kernel we 
will need to work directly with raw pointers. This is where
will use the `core::mem crate`. We need to check the size 
of data or the verifier will complain

```rust
    fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
        let start = ctx.data();
        let end = ctx.data_end();
        let len = mem::size_of::<T>();
        if start + offset + len > end {
            return Err(());
        }
        Ok((start + offset) as *const T)
    }
```

The packet parsing will be done in the try\_firewall\_001 function. We will peel off 
the layers of each packet till we match the rules passed in by the map IP

```rust
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; // 
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            info!(&ctx, "received IPv4 packet");
        }
        EtherType::Ipv6 => {
            info!(&ctx, "received IPv6 packet");
            return Ok(xdp_action::XDP_DROP);
        }
    
        _ => return Ok(xdp_action::XDP_PASS),
    }
```

We pass all IPv4 packets but drop any IPv6 packets, in the next section 
we start to unpack the IPv4 header, first we get the port 

```rust
    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*tcphdr).source })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).source })
        }
        _ => return Err(()),
    };
```

Then we check if the ip address is one in our list of blocked ip addresses
```rust
    if unsafe { SRC_IP_FILTER.get(&source_addr).is_some() } {
        info!(&ctx, "dropping packet ...");
        return Ok(xdp_action::XDP_DROP);
    }
```
The user space code reads a YAML config file that contains a list of IP addresses and
an instruction as to what to do to the packets coming from that address. 

```shell
    ---
    "127.0.0.1" : "block"
    "10.0.0.1"  : "block"
    "10.0.0.2"  : "block"
```
We will use the figment crate to parse the YAML config file into a 
hashmap that can be loaded into the eBPF map. 

Modify the Cargo.toml file in firewall-001/Cargo.toml to include
the dependency:

```cargo
    figment = { version = "0.10.18", features = ["yaml", "env"] }
```
And then add the following to the user space rust code in firewall-001/src/main.rs

```rust
    use std::net::Ipv4Addr;
    use figment::{Figment, providers::{Yaml, Format}};
    ...
    #[tokio::main]
    async fn main() -> Result<(), anyhow::Error> {
        let opt = Opt::parse();
        let config: HashMap<String,String> = Figment::new()
            .merge(Yaml::file("config.yaml"))
            .extract()?;
```
Here we extract the config file into a `HashMap<String,String>`
Once we have the entries from our config file in the a HashMap 
we can load them into the hashmap created in the ebpf code. 

This is the opposite of what we did in the Part 5 where
we data was stored in the map on the eBPF side and passed 
to the user space program. Here we load the data from user space
and pass it to the eBPF using the map.
```rust
    let mut src_ip_filter : ayaHashMap<_,  u32, u8> =
            ayaHashMap::try_from( bpf.map_mut("SRC_IP_FILTER").unwrap())?;
    ...
        for (k, v)  in config {
            if v == "block" {
                let addr : Ipv4Addr  = k.parse().unwrap();
                println!("addr {:?}" , addr);
                let _ = src_ip_filter.insert(u32::from(addr), 1, 0);
            }
        }
```
The IP addresses get loaded into the map and are then visible in the
eBPF code running in the kernel.

We can use the loopback address 127.0.0.1 to test whether the firewall works
First load the eBPF program and attach it to the loopback interface
```shell
    RUST_LOG=info cargo xtask run -- -i lo 
```
We can check that it is loaded using bpftool
```shell
    $ sudo bpftool prog list | grep -A 5 firewall
    5118: xdp  name firewall_002  tag 64a3874abd9070d2  gpl
            loaded_at 2024-05-01T23:27:54-0700  uid 0
            xlated 7008B  jited 3759B  memlock 8192B  map_ids 1532,1534,1533,1535
```
We can use the netcat program to test it. 
In one terminal start a server listening on port 9090
```shell
    nc -l 9090
```
In another terminal send data to the server:
```shell
    echo "the quick brown fox jumped over the lazy dog" |  nc 127.0.0.1 9090
```
In the terminal running the cargo command:
```shell
    2024-05-02T06:37:27Z INFO  firewall_002] received IPv4 packet
    [2024-05-02T06:37:27Z INFO  firewall_002] dropping packet ...
    ...
```
In the netcat server window there will no output showing receipt of a packet

