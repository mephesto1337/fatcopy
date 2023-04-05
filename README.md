# fatcopy

Copy files with (a lot) of similarities.
Typical use case is when you have to move a VM's disk back and forth 2 hosts.

It works along with SSH and a control master, by spawing a SSH process. 

## Usage

> ** Warning **
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
> This option is useful for transferring large files with block-based changes or appended data, and
> also on systems that are disk bound, not network bound.  It can also help keep a copy-on-write
> filesystem  snap‐ shot from diverging the entire contents of a file that only has minor changes.

This utility saves bandwith.

## How does it works ?

The protocol is pretty simple.
The sender sends first its filesize.

Then for each block (currently 4K size), the sender sends a SHA256 hash of the block along with its
size (indeed, the file's size is not necessary a multiple of 4K bytes). Then the receiver computes
the SHA256 on its side with the next `size` bytes.
If the hashes are the same, then the receivers sends an acknowledge and both moves towards the next
block. Otherwise, the receiver ask for the block's data and the sender sends it.
