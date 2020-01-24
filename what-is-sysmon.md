What is Sysmon
==============

Sysmon is a free tool initially developed by Mark Russinovich and has
contributions by Tomas Garnier, David Magnotti, Mark Cook, Rob Mead,
Giulia Biagini and others at Microsoft. The tool is designed to extend
the current logging capabilities in Windows with the goal to aid in
understanding and detecting attackers by behavior. It was developed
originally for internal use at Microsoft (There is still 2 versions of
the tool, one internal and another external. Currently the tool supports
64bit and 32bit systems and it uses a single command line tool for
installing and configuration management.

For ease of collection of the logs generated all the events generated
are saved in to Microsoft-Windows-Sysmon/Operational EventLog, this
allows current security products that already leverage collection from
the EventLog in Windows.

Sysmon is able to monitor for a series of actions on a Windows host that
relate to existing behavior that is abused by threat actors on, with
this view on the actions it allows defenders to better detect abnormal
behaviour and detect abuses on a system.

The table below shows the evet types and event ID for each.

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