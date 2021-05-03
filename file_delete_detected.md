File Delete Detected
====================

On version 13.10 of Sysmon added the capability to log file deletions without archiving the deleted file, the event is identical to **EventID 23** File Delete, for filtering the same fields are used. The File Delete Detected uses **EventID 26**.

It leverages the Sysmon minidriver and we should considered it altitude number when other security products are present.

![minifilter](./media/image36.png)

The minidriver monitors for three I/O request packets (IRP) IRP_MJ_CREATE, IRP_MJ_CLEANUP, and IRP_MJ_WRITE for file creates, complete handle closes, and writes respectively.


### Event information

The file delete event fields are:

* **RuleName**: Name of rule that triggered the event

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that deletec the file

* **ProcessId**: Process ID used by the OS to identify the process that deleted the file (child)

* **Image**: File path of the process that deleted the file

* **TargetFilename**: Name of the file that was deleted

**Hashes**: Full hash of the file with the algorithms in the HashType field. This is also the filename of the saved file in the ArchiveDirectory

This event type is recomended for those cases where there is a large number of false positive for a given rule but still it is of value to log the action or the rule has false positives for files that could be of great size like archive file or image files like ISO, IMG and others. 

