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

## Some numbers
To send a 1GB file between 2 PCs (disks speed does not count as they were stored in tmpfs) with a
1Gbit/s link and the default settings over an SSH connection.

For reference here is some speeds:

| Command run                                       | Time (in seconds) | Speed (Mbit/s) |
|---------------------------------------------------|-------------------|----------------|
| `cat file \| ssh host 'cat > file'`               |  9.244            | 886.20         |
| `cat file > /dev/tcp/1.2.3.4/1337`                |  9.110            | 899.24         |
| `rsync --inplace file host:same-file-at-99.99`    | 10.872            | 753.50         | 
| `rsync --inplace file host:same-file`             |  0.054            | A lot          |

Here are the results:

| Description of remote file  | Time (in seconds) | Speed (Mbit/s) |
|-----------------------------|-------------------|----------------|
| Completly random, same size | 10.438            |  784.83        |
| Completly random, half size | 9.848             |  831.85        |
| Empty                       | 9.218             |  888.70        |
| Same at 99%                 | 10.471            |  782.36        |
| Same at 99.9%               | 9.899             |  827.56        |
| Same at 99.99%              | 5.542             | 1478.18        |
| Same at 100%                | 5.467             | 1498.46        |
| Same at 99.9%, 85% size     | 6.026             | 1359.45        |
















