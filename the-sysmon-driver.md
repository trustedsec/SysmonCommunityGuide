The Sysmon Driver
=================

All of the monitoring is performed thanks to a driver that Sysmon installs called SysmonDrv. The driver will hook into Windows APIs and leverage Event Tracing for Windows (ETW) to capture the information on the actions it wants to monitor.

This Sysmon Driver has a unique altitude number of 385201 that determines the order of loading of the driver in comparison to other drivers on the system. Some blog posts recommend changing this number in the registry for obfuscation, but this may cause a conflict with another driver and prevent Sysmon from working or cause other errors on the system.

The driver is loaded by a service at system startup and a secondary service then queries the cached information.

![Sysmon Driver Behaviour](./media/image1.png )

For all file system operations, the driver registers as a Minifilter driver that is attached to volumes allowing it to see all actions taken by APIs before they are processed by the file system.

![Minifilter](./media/image2.png)

Sysmon sets multiple callbacks on kernel objects in addition to using telemetry APIs and ETW.

![kernel hook1](./media/image3.png)

![kernel hook2](./media/image4.png)

When the tool is downloaded from the Microsoft Sysinternals website <https://docs.microsoft.com/en-us/sysinternals/> it is important to save and identify previous versions since Microsoft does not provide older versions and the release notes do not detail what has been fixed. Microsoft has a fast release cycle, forcing users to test very carefully and to keep track of versions.


<table width="1280">
<tbody>
<tr>
<td width="132">
<p><strong>Version</strong></p>
</td>
<td width="114">
<p><strong>Schema </strong></p>
</td>
<td width="522">
<p><strong>Features</strong></p>
</td>
<td width="380">
<p><strong>Known Issues</strong></p>
</td>
<td width="132">
<p><strong>Release</strong></p>
</td>
</tr>
<tr>
<td width="132">
<p>12.0</p>
</td>
<td width="114">
<p>4.40</p>
</td>
<td width="522">
<p>* Added support to capture text stored in to the clipboard by a process.</p>
</td>
<td width="380">
<p>* Kernel memory write that can lead to code execution.</p>
<p>* Metadata for driver still references.</p>
<p>* Sysmon 11.1 and may affect install scripts.</p>
<p>* Problems matching filters for FileDelete.</p>
<p>* Blue Screen on some Windows 2016 DCs</p>
</td>
<td width="132">
<p>September 17, 2020</p>
</td>
</tr>
<tr>
<td width="132">
<p>11.1</p>
</td>
<td width="114">
<p>4.31</p>
</td>
<td width="522">
<p>* For Event ID 15 &ldquo;Content field was added to save text streams of less than 1k.</p>
<p>* The &ndash;a commandline option has been removed. The custom archive directory must be set via configuration file.</p>
<p>* Fix Issue where EventID 1 was not logged on Windowds 2016 and Windows 10.</p>
<p>* Fix rule parsing issue.</p>
</td>
<td width="380">
<p>* Kernel memory write that can lead to code execution.</p>
<p>* Blue Screen on on Win10 1809&nbsp;</p>
</td>
<td width="132">
<p>June 24, 2020</p>
</td>
</tr>
<tr>
<td width="132">
<p>11.0</p>
</td>
<td width="114">
<p>4.30</p>
</td>
<td width="522">
<p>* Control Reverse DNS Lookup.</p>
<p>* Log file deletions and story copy of the file.</p>
<p>* Bug Fixes.</p>
</td>
<td width="380">
<p>* Does not log Process Creation on Windows 2016.</p>
<p>* Kernel memory write that can lead to code execution.</p>
</td>
<td width="132">
<p>April 28, 2020</p>
</td>
</tr>
<tr>
<td width="132">
<p>10.42</p>
</td>
<td width="114">
<p>4.23</p>
</td>
<td width="522">
<p>* Fixed multiple memory leaks</p>
<p>* Introduces the "Excludes Any" and "Excludes All" filtering conditions</p>
</td>
<td width="380">
<p>* Issues with parsing some rules in configuration files.</p>
</td>
<td width="132">
<p>December 11, 2019</p>
</td>
</tr>
</tbody>
</table>

Another important piece of information is that there is no support from Microsoft on the Sysinternal tools—they are free and provided as is. This means that a testing plan for the environment it is deployed on should be formulated, tested, implemented, and improved upon as new versions of Sysmon are released.
