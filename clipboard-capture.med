Clipboard Capture
=================

Sysmon will log EventID 24 for when an application stores text in the clipboard. This capability was added in version 12.0 of Sysmon under schema 4.40.When text us stored the event is generated and the text that was copied in to clipboard is stored as a file referenced by the hash in the location specified for deleted files with the same protections on the folder so only applications running under the context of the SYSTEM account can list and read the files. If no folder is speciied Sysmon will create a folder under the root of the main drive with its name. 

The fields for the event are:

* **RuleName**: Name of rule that triggered the event.

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that stored the text in the clipboard.

* **ProcessId**: Process ID of the process that stored the text in the clipboard.

* **Image**: The process that recorded to the clipboard.

* **Session**: Session where the process writing to the clipboard is running. This can be system(0) interactive or remote, etc.

* **ClientInfo**: this will contain the session username, and in case of a remote session the originating hostname, and the IP address when available.

* **Hashes**: This determines the file name, same as the FileDelete event.

* **Archived**: Status whether is was stored in the configured Archive directory.

As it is obivios this type of data is sensitive since it may contain code, credentials, persona identifiable informatior or more. This is one of the reasons that the data is not stored in the eventlog but in the heavily permissioned folder. Because of this certain care should be taken when deciding on what systems it would be of value to enable this kind of logging, 
