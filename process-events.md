
Process Events
==============

Sysmon can log process creation, process termination and process access
events. The prorocess actions are captured via ObjRegisterCallbacks at
the kernel level using its driver. These events are important since the
**ProcessGuid** field of these events are used by other so as to provide
more context on the process that relates to the actions and the
ProcessGuid maps to the **LogonGuid** that it is then used to track all
actions of a given logon session. The main reason for using this GUIDs
is that Process ID and Logon ID on a system get re-used as time passes.
In the case of processes ID it can happen multiple times in a days.

![ProcessGUID Source](./media/image31.png)

When a user logs onto on a modern version of Windows (Windows 2016/10)
they will have 2 Logon IDs assigned if:

* User is a member of local Administrator Group.

* UAC (User Access Control) is enabled.

These sessions will be linked by a Linked Login ID in Successful Logon
Event ID 4624, making the login of this event important.

The ProcessGUID depending on the event and where in the process tree it
is, it will also be known by other names by its relation to the action
monitored

![ProcessGUID Relation](./media/image32.png)

The only Event Types that will not reference a ProcessGuid or one of its
derived names are

* WMI events

* Kernel Driver Load

The image of the process is also related in other processes and can be
used to track all actions related to a specific one.

![Image Relation](./media/image33.png)
