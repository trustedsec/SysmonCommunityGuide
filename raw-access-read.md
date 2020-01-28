Raw Access Read
===============

Sysmon will log **EventID 9** for any process trying to read straight from a storage device by bypassing any filesystem restrictions that may be imposed by it. This information is logged by Sysmon leveraging its minifilter. This type of action is only done by drive imaging software or backup software in a normal operating environment.

Attackers have been known to use this technique to copy NTDS.dit and SAM Registry Hives off host for the purpose of credential harvesting.

The fields for the event are:

* **RuleName**: Name of rule that triggered the event

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process GUID of the process that conducted reading operations from the drive

* **ProcessId**: Process ID used by the OS to identify the process that conducted reading operations from the drive

* **Image**: File path of the process that conducted reading operations from the drive

* **Device**: Target device

Given that no process should be performing this action normally, it is best to log all instances of it or, even better, to target the NTDS.dit file on domain controllers and SAM hive file on all systems. On systems with many file modifications, slightly higher resource usage may result if monitoring is enabled for all files.

Example that captures all instances of this event

![collect all](./media/image60.png)
