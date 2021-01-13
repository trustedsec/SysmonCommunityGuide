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
<tr style="height: 46px;">
<td style="height: 46px;" width="132">
<p><strong>Version</strong></p>
</td>
<td style="height: 46px;" width="114">
<p><strong>Schema </strong></p>
</td>
<td style="height: 46px;" width="522">
<p><strong>Features</strong></p>
</td>
<td style="height: 46px;" width="132">
<p><strong>Release</strong></p>
</td>
</tr>
<tr style="height: 46px;">
<td style="height: 46px;" width="132">
<p>13.01</p>
</td>
<td style="height: 46px;" width="114">4.50&nbsp;</td>
<td style="height: 46px;" width="522">&nbsp;* Fixed regression bug where several event types where not logged.&nbsp;</td>
<td style="height: 46px;" width="132">&nbsp;January 13, 2021</td>
</tr>
<tr style="height: 46px;">
<td style="height: 46px;" width="132">
<p>13.0</p>
</td>
<td style="height: 46px;" width="114">&nbsp;4.50</td>
<td style="height: 46px;" width="522">&nbsp;* Added support for Process Tampering Detection.</td>
<td style="height: 46px;" width="132">&nbsp;January 11, 2021</td>
</tr>
<tr style="height: 61px;">
<td style="height: 61px;" width="132">12.03</td>
<td style="height: 61px;" width="114">&nbsp;4.40</td>
<td style="height: 61px;" width="522">&nbsp;* fixes reporting and a possible crash condition for PipeEvent and RegistryEvent rules.</td>
<td style="height: 61px;" width="132">&nbsp;November 25, 2020</td>
</tr>
<tr style="height: 61px;">
<td style="height: 61px;" width="132">12.02</td>
<td style="height: 61px;" width="114">&nbsp;4.40</td>
<td style="height: 61px;" width="522">&nbsp;* This update to Sysmon fixes several configuration parsing bugs.</td>
<td style="height: 61px;" width="132">&nbsp;November 4, 2020</td>
</tr>
<tr style="height: 61px;">
<td style="height: 61px;" width="132">12.01</td>
<td style="height: 61px;" width="114">&nbsp;4.40</td>
<td style="height: 61px;" width="522">&nbsp;* Security and bug fix release, resolves a PipeEvent processing issue and adds extra checks to kernel writes.</td>
<td style="height: 61px;" width="132">&nbsp;October 16, 2020</td>
</tr>
<tr style="height: 192px;">
<td style="height: 192px;" width="132">
<p>12.0</p>
</td>
<td style="height: 192px;" width="114">
<p>4.40</p>
</td>
<td style="height: 192px;" width="522">
<p>* Added support to capture text stored in to the clipboard by a process.</p>
</td>
<td style="height: 192px;" width="132">
<p>September 17, 2020</p>
</td>
</tr>
<tr style="height: 196px;">
<td style="height: 196px;" width="132">
<p>11.11</p>
</td>
<td style="height: 196px;" width="114">
<p>4.4</p>
</td>
<td style="height: 196px;" width="522">
<p>* Fixes a bug that prevented USB media from being ejected.</p>
<p>* Fixes an issue that could stop network event logging and a resulting memory leak.</p>
<p>* Fixes logs file delete events for delete-on-close files.</p>
</td>
<td style="height: 196px;" width="132">
<p>July 15, 2020</p>
</td>
</tr>
<tr style="height: 196px;">
<td style="height: 196px;" width="132">
<p>11.1</p>
</td>
<td style="height: 196px;" width="114">
<p>4.31</p>
</td>
<td style="height: 196px;" width="522">
<p>* For Event ID 15 &ldquo;Content field was added to save text streams of less than 1k.</p>
<p>* The &ndash;a commandline option has been removed. The custom archive directory must be set via configuration file.</p>
<p>* Fix Issue where EventID 1 was not logged on Windowds 2016 and Windows 10.</p>
<p>* Fix rule parsing issue.</p>
</td>
<td style="height: 196px;" width="132">
<p>June 24, 2020</p>
</td>
</tr>
<tr style="height: 110px;">
<td style="height: 110px;" width="132">
<p>11.0</p>
</td>
<td style="height: 110px;" width="114">
<p>4.30</p>
</td>
<td style="height: 110px;" width="522">
<p>* Control Reverse DNS Lookup.</p>
<p>* Log file deletions and story copy of the file.</p>
<p>* Bug Fixes.</p>
</td>
<td style="height: 110px;" width="132">
<p>April 28, 2020</p>
</td>
</tr>
<tr style="height: 78px;">
<td style="height: 78px;" width="132">
<p>10.42</p>
</td>
<td style="height: 78px;" width="114">
<p>4.23</p>
</td>
<td style="height: 78px;" width="522">
<div>* Memory&nbsp;leaks&nbsp;in&nbsp;DNS,&nbsp;Networking&nbsp;and&nbsp;Image&nbsp;load&nbsp;events</div>
<div>* Bug&nbsp;fixes&nbsp;including&nbsp;filtering,&nbsp;rule&nbsp;group&nbsp;names,&nbsp;NULL&nbsp;process&nbsp;GUIDS&nbsp;and&nbsp;W3LOGSVC&nbsp;interop&nbsp;issue</div>
<div>* Increased&nbsp;rule&nbsp;name&nbsp;field&nbsp;length&nbsp;from&nbsp;32&nbsp;to&nbsp;128&nbsp;characters</div>
<div>* Added&nbsp;&ldquo;excludes&nbsp;any&rdquo;&nbsp;and&nbsp;&ldquo;excludes&nbsp;all&rdquo;&nbsp;filtering&nbsp;conditions.</div>
<div>* Performance&nbsp;improvements&nbsp;for&nbsp;ImageLoad&nbsp;module</div>
</td>
<td style="height: 78px;" width="132">
<p>December 11, 2019</p>
</td>
</tr>
</tbody>
</table>

Another important piece of information is that there is no support from Microsoft on the Sysinternal tools—they are free and provided as is. This means that a testing plan for the environment it is deployed on should be formulated, tested, implemented, and improved upon as new versions of Sysmon are released.
