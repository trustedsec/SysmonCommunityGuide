Raw Access Read
===============

Sysmon will log **EventID 9** any process trying to read straight from
the device bypassing all filesystem restrictions a given file leveraging
its minifilter. This type of action is only done by drive imaging
software or backup software in a normal operating environment.

Attackers have been known to use this technique to copy NTDS.dit and SAM
Registry Hives off host for the purpose of credential harvesting.

The fields for the event are:

* **RuleName**: Name of rule that triggered the event.

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that conducted reading
    operations from the drive

* **ProcessId**: Process ID used by the OS to identify the process
    that conducted reading operations from the drive

* **Image**: File path of the process that conducted reading
    operations from the drive

* **Device**: Target device

Given that normally no process should be performing this action it is
best to log all instances of it or even better to target the NTDS.dit
file on domain controllers and SAM hive file on all systems. On systems
with lots of file modifications it may cause slightly higher resource
usage if enabled to monitor all files.

Example that captures all instances of this event

![collect all](./media/image60.png)