sysinternalsEBPF
=================

 Sysmon for Linux uses its own library “sysinternalsEBPF” to handle the security events monitoring process. The advantages are that eBPF is a technology that allows programs to run in a sandbox in an operating system at the kernel level. The eBPF library will allow for the collection of information on:

 - Processes
 - System Calls
 - Network Sockets

 The “sysinternalsEBPF” library is open sourced and licensed under the MIT License. The source is available in GitHub at https://github.com/Sysinternals/SysinternalsEBPF In GitHub the latest installation and build instructions can be found. 

![Bind Event](media/image64.png)

The eBPF library leverages a large library of Kernel memory offsets that are stored after installation in a JSON file at 