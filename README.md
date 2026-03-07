# Topomap

A lightweight service topology mapper that tells you what is running on your machines, what is talking to what, and what you need to pay attention to.

## The Problem

It is 2 AM, something is down, and you need answers fast.

Maybe you just got pulled into an incident and barely know how the system is put together. Or you are a new dev onboarding into a codebase and the architecture documentation is either outdated or nonexistent. Perhaps you are on blue team in a live engagement and the attackers have persistence on your network.

In all of these cases, you need the same thing: a clear picture of what is running, how it is connected, and where to look.

Tracing through documentation while services are down is not the best feeling in the world. Reading source code to guess what services talk to each other is slow. Network topology diagrams alone do not tell you what processes own which ports or what connections are actually live right now.

And if you do not have a SIEM or monitoring stack set up (or if the attacker already compromised it), you are flying blind.

## What Topomap Does

Topomap gives you a live snapshot of your entire service topology across multiple machines from a single control point.

For every machine you point it at, it tells you:

What processes are running and what binaries they are.
What ports each process is listening on.
What each process is connected to, both locally and across the network.
What changed since the last time you looked.
What looks exposed, unresolved, or suspicious.

It does this without installing anything on the target machines.

## How It Works

Linux processes are files. Everything about a running process, its binary, its connections, its file descriptors, is exposed through the `/proc` filesystem. Topomap reads these files directly.

1. A small static binary gets pushed to each target machine over SSH.
2. The binary reads /proc to collect all running processes, their socket inodes, network connections (TCP, UDP, IPv4, IPv6, Unix sockets), executables, command lines, and cgroup information.
3. The data is serialized into a compact binary wire format and streamed back to the control machine over the same SSH connection.
4. The binary is deleted from the target immediately after execution. It runs from /dev/shm so it never touches disk.
5. On the control machine, snapshots from all nodes are cross referenced to resolve the full service topology: which process on which machine talks to which process on which other machine, through which ports.

Determining which process owns which connections id done with the help of a hashmap. Process scanning is parallelized across threads. Network file reads (tcp, udp, tcp6, udp6, unix) run concurrently.

## Features

**Live topology mapping.** See every service, every connection, every port across all your machines in one view. Cross node connections, loopback dependencies, and Unix socket relationships are all resolved.

**Connection state diffing.** Every scan is compared against the previous snapshot. New connections, dropped connections, state changes, new services, and disappeared services are reported.

**Attack surface reporting.** Topomap flags every process listening on 0.0.0.0 (exposed to the network), lists all ports that need traffic capture, identifies cross node paths that should be firewalled, and highlights unknown outbound destinations that need investigation.

**Hardening checklist.** After every topology map, a checklist is generated listing the specific ports to monitor, the cross node paths to firewall or log, and the unresolved external connections to investigate.

**Interactive control plane.** A REPL lets you enroll nodes, run scans, view reports, inspect the topology map, and execute shell commands on remote machines. Adding new commands is declarative: define a name, a function pointer, and a help string.

**Persistent sessions.** Snapshots are saved to disk in binary format. When you restart Topomap, it reloads all previous snapshots and re enrolls the nodes automatically. Unenrolling a node dumps a final human readable report to the work directory before removing it.

**Remote execution.** Push and execute binaries on target machines using the same transport as the scanner. Or run shell commands directly. Both go through the established SSH key infrastructure with scoped sudo permissions.

## Dependencies

CMake.

The scanner binary compiles as a fully static executable with no runtime dependencies. It runs on any Linux system regardless of what is or is not installed. The control plane binary needs pthreads, which is part of every Linux distribution.

## Preconditions

You are on a central machine with SSH access to the targets.
You have login credentials on the targets with root privilege (direct root or sudo).
Target machines are running Linux with `/proc` available.

Since Topomap reads directly from `/proc`, it works on any Linux based operating system. This covers the majority of enterprise server infrastructure: Debian, Ubuntu Server, RHEL, Amazon Linux, Rocky Linux, AlmaLinux, SUSE, Oracle Linux, and anything running on AWS, GCP, or Azure. If it boots a Linux kernel, Topomap can read it. This includes bare metal, VMs, and Kubernetes nodes.

> Note: Container credentials usually do not have root privilege. Luckily, containers are just processes on the host, so the node level report will still show you what is running inside them and how they are connected. 

## Quick Start

Build:
```
./build_bin.sh
```

Run:
```
./build/bin/dispatcher
```

This will start up the REPL

From there:
```
surveyor> list                        # show enrolled nodes
surveyor> scan                        # scan all nodes
surveyor> scan 10.0.0.1               # scan one node
surveyor> report                      # print all node reports
surveyor> report 10.0.0.1 out.txt     # save report to file
surveyor> map                         # print full topology map
surveyor> exec shell 10.0.0.1 ss -tnp # run a command on a node
surveyor> enroll 10.0.0.4 admin       # add a new node
surveyor> unenroll 10.0.0.2           # remove a node
surveyor> help                        # list all commands
```

## Who This Is For

**Incident responders** who just got paged and need to understand what is running and what is talking to what before they can start triage.

**Blue teamers in live engagements** who need to rapidly assess what services are exposed, what connections exist, and what changed since the last scan. If you compete in events like the Collegiate Cyber Defense Competition (CCDC), this tool is built for the kind of high pressure, low information, time critical environment where every second of orientation matters.

**Developers and SREs joining a new team** who need to understand the gist of how the production system fits together.

**Anyone operating in degraded conditions** where the monitoring stack is down, compromised, or was never set up. Topomap works as long as SSH works. It carries no state on the target, leaves no trace on disk, and does not depend on any other infrastructure being healthy.

## Design Principles

**Minimal footprint.** The scanner binary is a single static executable that runs from RAM, executes in seconds, and deletes itself. Nothing is installed on the target.

**No external dependencies.** Everything is built from scratch in C using POSIX interfaces and the `/proc` filesystem.

**Speed.** Hash maps for O(1) lookups, thread pools for parallel scanning, linked list collection with single allocation flattening. The goal is to get answers in seconds during situations where seconds matter.

**Readable output.** Reports are structured for quick scanning: attack surface first, then connections by priority (cross node, same node, loopback, unix socket), then unresolved unknowns, then a concrete hardening checklist.

## Note

I built this tool based on problems I ran into during CCDC and during an actual incident, where the given network topology and documentations were not enough for me to understand what is going on. I am not a security expert, but I hope it can be useful to someone in a similar situation.