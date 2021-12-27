File Delete
===========

On version 11.0 of Sysmon the capability to log file deletions was added, in addition file marked for deletion are archived allowing defentders to collect tools and other files an attacker creates on a system to better track and understand their activiries. Sysmon relies on its filter driver, Sysmon can log the creation of files and information on what process is deleting or overwriting the file using **EventID 23**. Defender can use this event type to filter for:

* Dropper / stager that removes itself after execution (T1193 or T1064 and loads more) or attackers doing it manually

* Wiper software (T1485 and T1488)

* Ransomware (T1486)

![minifilter](./media/image36.png)

The minidriver monitors for three I/O request packets (IRP) IRP_MJ_CREATE, IRP_MJ_CLEANUP, and IRP_MJ_WRITE for file creates, complete handle closes, and writes respectively.


### Archive directory

By default this folder is set to Sysmon if no folder is specified during installation and specified either in the configuration either in config file with the ```<ArchiveDirectory>``` setting in XML configurations file or via the registry by setting the registry key value **FilterArchiveDirectory** under the  driver registry key paramaters.

On version 11.0 of Sysmon if the folder is not created during install using the commandline **-a \<folder name\>** parameter Sysmon will use the default **Sysmon** folder name and create that one and not the one specified in the configuration. On version 11.1 of Sysmon the parameter was removed and it is now required to specify the folder in the XML configuration file or the default name will be used. 
    
This folder is protected by a SYSTEM ACL, to access it you can use psexec to spawn a shell to access it via ```PsExec.exe -sid cmd```.

```
PS C:\> (Get-Acl C:\Sysmon\).access


FileSystemRights  : FullControl
AccessControlType : Allow
IdentityReference : NT AUTHORITY\SYSTEM
IsInherited       : False
InheritanceFlags  : None
PropagationFlags  : None
```

### Event information

The file delete event fields are:

* **RuleName**: Name of rule that triggered the event

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that deletec the file

* **ProcessId**: Process ID used by the OS to identify the process that deleted the file (child)

* **Image**: File path of the process that deleted the file

* **TargetFilename**: Name of the file that was deleted

**Hashes**: Full hash of the file with the algorithms in the HashType field. This is also the filename of the saved file in the ArchiveDirectory

* **Archived**: States whether the archival action was succesful

Example monitoring for script file creation by extension:

```XML
<Sysmon schemaversion="4.30">
<ArchiveDirectory>SysmonIsAwesome</ArchiveDirectory>
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <FileCreate onmatch="include">
                <Rule groupRelation="or">
                    <TargetFilename condition="contains">\Downloads\</TargetFilename> <!--Download folder -->
                    <TargetFilename condition="end with">\Content.Outlook\</TargetFilename> <!--Outlook Temporary Internet files-->
                    <TargetFilename condition="end with">\AppData\Local\Temp\</TargetFilename>
                    <TargetFilename condition="end with">\AppData\Local\Microsoft\</TargetFilename> <!--Office temp files-->
                    <TargetFilename condition="begin with">C:\Windows\Temp</TargetFileName>
                </Rule>

                <!-- File extension options -->
                <TargetFilename condition="contains any">.exe;.ps1;.js;.xls;.xlsm;.docm</TargetFileName>
            </FileCreate>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

### Warning

A code execution vulnerability exits on Sysmon 11.0, 11.1 and 12.0 where an attacker that has local administrative privileges can leverage a bug in the way that Sysmon handles File Delete events in its memory allows for arbitrary kernel write where an attacker can write executacle code and run it with kernel level privileges. 

SHA1 hashes for vulnerables version of the drivers are:

* 35c67ac6cb0ade768ccf11999b9aaf016ab9ae92fb51865d73ec1f7907709dca
* d2ed01cce3e7502b1dd8be35abf95e6e8613c5733ee66e749b972542495743b8
* a86e063ac5214ebb7e691506a9f877d12b7958e071ecbae0f0723ae24e273a73
* c0640d0d9260689b1c6c63a60799e0c8e272067dcf86847c882980913694543a
* 2a5e73343a38e7b70a04f1b46e9a2dde7ca85f38a4fb2e51e92f252dad7034d4
* 98660006f0e923030c5c5c8187ad2fe1500f59d32fa4d3286da50709271d0d7f
* 7e1d7cfe0bdf5f17def755ae668c780dedb027164788b4bb246613e716688840

Using a SIEM one can monitor for this hashes using Sysmon Event ID 6 for driver loads. Also access to the sysmon service executable should be monitor for SourceImage and GrantedAccess masks not seen before.  
