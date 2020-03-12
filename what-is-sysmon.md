What is Sysmon
==============

Sysmon is a free tool initially developed by Mark Russinovich and has contributions by Tomas Garnier, David Magnotti, Mark Cook, Rob Mead, Giulia Biagini, and others at Microsoft. The tool is designed to extend the current logging capabilities in Windows to aid in understanding and detecting attackers by behavior. It was developed originally for internal use at Microsoft. (Note: There are still two versions of the tool—internal and external.) Currently, the tool supports 64-bit and 32-bit systems and uses a single command line tool for installation and configuration management.

For ease of collecting the logs, all of the events generated are saved in Microsoft-Windows-Sysmon/Operational EventLog, which allows current security products that already leverage collection from the EventLog in Windows.

Sysmon is able to monitor for a series of actions on a Windows host that relate to existing behavior that is abused by threat actors. With this view on the actions, defenders are able to better detect abnormal behavior and abuses on a system.

The table below shows the event types and event ID for each.

| EventType| EventId|
|---|---|
|Sysmon Service Status Changed|0
|ProcessCreate|1
|FileCreateTime|2
|NetworkConnect|3
|Service State Change|4
|ProcessTerminate|5
|DriverLoad|6
|ImageLoad|7
|CreateRemoteThread| 8
|RawAccessRead| 9
|ProcessAccess| 10
|FileCreate| 11
|Registry object added or deleted | 12
|Registry Create| 13
|Registry Rename| 14
|FileCreateStreamHash | 15
|Sysmon Config Change| 16
|Named Pipe Create| 17
|Named Pipe Connected|18
|WMI Event Filter|19
|WMI Event Consumer|20
|WMI Consumer to Filter|21
|DNS Query|22
|Error|255
