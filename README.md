
<p><img align="left" width="100" height="100" src="media/tslogo.png"></p>


# The Sysmon CommunityGuide



<p align="center"><a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/" style="display: inline-block; float: left; vertical-align: middle; margin: 10px;"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a></p>

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-sa/4.0/), please attribute to TrustedSec Inc


[Table Of Contents](#table-of-contents)

###### You are free to:

**Share** — copy and redistribute the material in any medium or format.

**Adapt** — remix, transform, and build upon the material.

The authors encourage you to redistribute this content as widely as possible, but require that you give credit to the primary authors below, and that you notify us on GitHub of any improvements you make.


Table of Contents
=================

* [What is Sysmon](./what-is-sysmon.md)

* [The Sysmon Driver](./the-sysmon-driver.md)

* [Install and Configuration](./install-and-configuration.md)

* Sysmon Events

  * [Process Events](./process-events.md)

    * [Process Creation](./process-creation.md)

    * [Process Termination](./process-termination.md)

    * [Process Access](./process-access.md)

  * File Events
  
    * [File Create](./file-create.md)

    * [File Create Time Change](./file-create-time-change.md)

    * [File Stream Creation Hash](./file-stream-creation-hash.md)

  * [Named Pipes](./named-pipes.md)

  * [Driver Loading](./driver-loading.md)

  * [Registry Actions](./registry-actions.md)

  * [Image Loading](./image-loading.md)

  * [Network Connections](./network-connections.md)

  * [Create Remote Thread](./create-remote-thread.md)

  * [Raw Access Read](./raw-access-read.md)

  * [DNS Query](./dns-query.md)

  * [WMI Events](./WMI-events.md)
  
## Current State:

Microsoft Sysinternals Sysmon is an ever changing piece of software provided by Microsoft free for its users. As such it is constantly being updated and new featured are added. As it relates to configurations this guide tries to be as open as possible since each environment is unique and recomendations are based on these contraints as much as possible. The guide is made Open Source so that as Sysmon evolves the comunity helps in expanding and maintaining the guide. 

## Contributing

Please use the issues system or GitHub pull requests to make corrections, contributions, and other changes to the text - we welcome your contributions!

## Credits

This guide was originally written and edited by Carlos Perez of TrustedSec LLC.

- **[MIT license](http://opensource.org/licenses/mit-license.php)**
- Copyright 2020 © <a href="https://www.trustedsec.com/" target="_blank">TrustedSec</a>.
