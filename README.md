
<p><img align="left" width="100" height="100" src="chapters/media/tslogo.png"></p>

# TrustedSec Sysmon Community Guide

<p align="center"><a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/" style="display: inline-block; float: left; vertical-align: middle; margin: 10px;"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a></p>

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-sa/4.0/), please attribute to TrustedSec LLC

###### You are free to:

**Share** — copy and redistribute the material in any medium or format.

**Adapt** — remix, transform, and build upon the material.

The authors encourage you to redistribute this content as widely as possible, but require that you give credit to the primary authors below, and that you notify us on GitHub of any improvements you make.

Table of Contents
=================

* [What is Sysmon](./chapters/what-is-sysmon.md)

* Sysmon on Windows

  * [The Sysmon Driver](./chapters/the-sysmon-driver.md)

  * [Install and Configuration](./chapters/install_windows.md)

* Sysmon on Linux
  
  * [sysinternalsEBPF](./chapters/eBPF.md)

  * [Install and Configuration](./chapters/install_linux.md)

* [Configuration](./chapters/configuration.md)

* [Detection Engineering Fundamentals](./chapters/detection-engineering.md)
  
* Sysmon Events

  * [Process Events](./chapters/process-events.md)

    * [Process Creation](./chapters/process-creation.md)

    * [Process Termination](./chapters/process-termination.md)

    * [Process Access](./chapters/process-access.md)

  * File Events
  
    * [File Create](./chapters/file-create.md)

    * [File Create Time Change](./chapters/file-create-time-change.md)

    * [File Stream Creation Hash](./chapters/file-stream-creation-hash.md)

    * [File Delete](./chapters/file-delete.md)

    * [File Delete Detected](./chapters/file_delete_detected.md)

    * [File Block EXE](./chapters/file-block-exe.md)
    
    * [File Block Shredding](./chapters/file-blockshredding.md)

  * [Named Pipes](./chapters/named-pipes.md)

  * [Driver Loading](./chapters/driver-loading.md)

  * [Registry Actions](./chapters/registry-actions.md)

  * [Image Loading](./chapters/image-loading.md)

  * [Network Connections](./chapters/network-connections.md)

  * [Create Remote Thread](./chapters/create-remote-thread.md)

  * [Raw Access Read](./chapters/raw-access-read.md)

  * [DNS Query](./chapters/dns-query.md)

  * [WMI Events](./chapters/WMI-events.md)
  
  * [Clipboard Capture](./chapters/clipboard-capture.md)
  
  * [Process Image Tampering](./chapters/process-tampering.md)
  
## Current State:

Microsoft Sysinternals Sysmon is an ever changing piece of software provided by Microsoft free for its users. As such it is constantly being updated and new featured are added. As it relates to configurations this guide tries to be as open as possible since each environment is unique and recomendations are based on these contraints as much as possible. The guide is made Open Source so that as Sysmon evolves the comunity helps in expanding and maintaining the guide. 

## Contributing

Please use the issues system or GitHub pull requests to make corrections, contributions, and other changes to the text - we welcome your contributions!

## Credits

This guide written, maintained and edited by Carlos Perez of TrustedSec LLC.

- Copyright 2025 © <a href="https://www.trustedsec.com/" target="_blank">TrustedSec LLC</a>.
