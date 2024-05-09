---
title: Aya Rust tutorial Part One
date: "2024-05-09"
toc: false
tags:
	- "ebpf"
	- "rust"
	- "linux"
	- "aya"
---
&copy; steve latif 

# Getting started with Aya and eBPF Part 1

## Introduction

This is the first in a series of posts looking at eBPF and the
Rust Aya crate. eBPF can run sandboxed programs inside the kernel.
Aya can create the byte code for both the kernel space
programs, and the corresponding  userland programs to load the eBPF byte code.

The Extended Berkeley Packet Filter came out as a development on 
the Berkeley Packet Filter
dating back to the early 1990s. 
BPF based tools tcpdump, ethereal and 
the libpcap libraries were used to capture
network packets on the wire, filter them, even inject faults. 
Doing anything  other than monitoring packets was a time intensive and tricky 
operation. More information on eBPF can be found here: <https://ebpf.io/>

Rust has been around for several years and works well as a system and 
general programming language. There are many fine introductions to the language,
a good place to start is here: <https://www.rust-lang.org/>

In this series of articles we will be looking at 
aya-rs, a rust interface to eBPF <https://aya-rs.dev/>

Two past projects act as motivation for my work with 
eBPF and aya.


## Scenario 1 SMB Traffic generation

The network interface on 
a storage filer was locking up after having 
mounted 255 SMB network shares. 
To emulate this we had a lab that consisted of:

-   a linux client box
-   smbclient, an FTP like interface to Samba
-   Maxwell Pro from Interworking Labs (iwl.com) to rewrite ethernet headers.

Quick side note on the Maxwell Pro, it 
consists of a linux box with two ethernet cards, packets coming in are passed to 
a user space application, where they can be modified or have their headers
rewritten, they are then passed out from the other interface.
![img](./images/maxwell_pro.png)

This had to be thrown together in a few days using whatever was at hand.

Here's a schematic of the setup, bear in mind that this is Linux circa 2004, 
Linux networking was more limited in its capabilities. 
![img](./images/smb_test_bed.png)

This would simulate from several hundred, to several thousand windows computers
mounting a network share. The share requests would come in from distinct IP and MAC 
addresses.

There are 3 hosts:

-   a linux client
    -   Depending on the test, this will have between 300 - 5000 virtual IP addresses, each with a unique IP
-   An IWL Maxwell Pro to rewrite the ethernet headers (iwl.com)
-   The device under test: An SMB server

The procedure:

-   A C wrapper script would run multiple invocations of smbclient 
    -   each smblcient invocation would have it's socket call intercepted and bound to one of the IP addresses 
        using the dynamic linking loader <https://man7.org/linux/man-pages/man3/dlopen.3.html>
    
    -   The Maxwell Pro would rewrite the outgoing MAC address to one based on the IP address
    -   SMB server would respond to the smbclient request
    -   The response packets would be intercepted by the Maxwell Pro which would rewrite the SMB server response so that the MAC address was the actual MAC on the linux client

If we were to try to get this working now, could we do it in a more robust manner and not have:

-   The Maxwell Pro
-   Manipulating the dynamic linking loader
-   All the virtual interfaces

Using eBPFs packet parsing and rewriting abilities we could might be able 
to do all or some of these. 

One of the major headaches with the original project was that it had several disparate 
elements implemented in different languages. This was a result of the ad hoc nature of the project.
Being able to build it in a consistent and robust manner would be a major plus.


## Scenario 2 Wan Simulation

In this case the ask was to build a wan simulator between two servers to 
test acceleration algorithms. The product was a server that might sit in 
a remote office and communicate with a similar server in a corporate 
data center. Traffic would between the two boxes tunneled and cached 
to deal with low bandwidth lossy links.
From the networking perspective this 
was more straight forward as it involved using a traffic shaping and 
firewalling tool to simulate different WAN scenarios. Most of the work 
ended up being in the reporting side of the project. 

The traffic shaper/firewall was a FreeBSD tool called dummynet: <http://info.iet.unipi.it/~luigi/dummynet/>

There were many combinations to test the algorithms in. Stability and consistency 
was always a concern. 

![img](./images/wan_emulator.png)

## Why Use eBPF and Aya?

Both these projects had rapid turnarounds from conception to implementation,
but parts of them were quite fragile. My regret was that I didn't have 
full access to the networking stack to manipulate packets as they passed
through the stack. eBPF goes a long way to giving us this ability with some
restrictions.
The SMB trafiic generator had small pieces of code in C for running smbclient, 
Perl for setting up the networking environment, C++ for running 
in the Maxwell Pro to rewrite the ethernet headers. Building and testing
these small programs could only be done on the hosts where they would run
for the most part. Deployment involved using rsync/sftp to move files around.
Not having a consistent build CI pipeline incurs overhead. 
There was a similar situation for the WAN emulator. The traffic shaping tool
was part of the FreeBSD kernel which required a kernel rebuild to deploy it 
and could only be tested once in place.

Aya allows you to use eBPF, but also build both your userspace and kernel 
code with one command using Cargo. Testing and deployments are now
much easier. There are other language bindings to use eBPF, several 
of which are relatively mature. Rust does have more stringent requirements
during the compilation phase for code hygiene. This can only be a good thing
when generating code that will be run with escalated privileges.


## Next Steps

The first goal will be to learn enough about Aya and eBPF to see if we can
implement, or at least think of implementing some parts of the traffic 
generator and traffic shaper. These are esoteric tools
but the ideas that we will need for implementing them will mean that 
we can talk about

-   firewalls
-   load balancers
-   networking protocols

