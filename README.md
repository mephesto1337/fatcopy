# fatcopy

Copy files with (a lot) of similarities.
Typical use case is when you have to move a VM's disk back and forth 2 hosts.

It works along with SSH and a control master, by spawing a SSH process. 

## Usage

> :warning: Warning
> the binary must be in the path of the remote host

```bash
fatcopy /var/lib/libvirt/images/vm.qcow2 other-host:/var/lib/libvirt/images/vm.qcow2
```

## Why can I just ue rsync ?

You could use rync with the following command:
```bash
rsync -aP --checksum --inplace -e ssh /var/lib/libvirt/images/vm.qcow2 other-host:/var/lib/libvirt/images/vm.qcow2
```

But as rsync's documentation states:
> **--inplace**
> [...]
> This option is useful for transferring large files with block-based changes or appended data, and
> also on systems that are disk bound, not network bound.  It can also help keep a copy-on-write
> filesystem  snap‐ shot from diverging the entire contents of a file that only has minor changes.

This utility saves bandwith.

## How does it works ?

The protocol is pretty simple.

1. Both server and client sends their size.

2. Until the server reaches the minimum of its size and the client:
  - The servers reads `bulk_size * block_size` of data and sends SHA256 hash of each block
  - The client also reads `bulk_size * block_size` and compare with the received hashes
  - If a hash match, then `Ok` is returned, otherwise `DataNeeded` is sent (in bulk)
  - If the server received any `DataNeeded`, then the slice of dat is sent.

3. The server has the smaller size, then we are done. Otherwise the server will on send data's
   blocks. As the client has a smaller size, hashes will not match.
