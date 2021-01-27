Clipboard Capture
=================

Sysmon will log EventID 24 for when an application stores text in the clipboard. This capability was added in version 12.0 of Sysmon under schema 4.40.When text us stored the event is generated and the text that was copied in to clipboard is stored as a file referenced by the hash in the location specified for deleted files with the same protections on the folder so only applications running under the context of the SYSTEM account can list and read the files. If no folder is speciied Sysmon will create a folder under the root of the main drive with its name. 

Before creating filters for event a element of **\<CaptureClipboard\/\>** need to be added under the sysmon element. Once this element is added you can create filters for the event type. The **\<ArchiveDirectory\>** element in the configuration XML controls the location of the saved text. 

As it is obivios this type of data is sensitive since it may contain code, credentials, persona identifiable informatior or more. This is one of the reasons that the data is not stored in the eventlog but in the heavily permissioned folder. Because of this certain care should be taken when deciding on what systems it would be of value to enable this kind of logging. Recomended system would be servers that have RDP enabled, specially those exposed to untrusted networks. It is important to make sure that administrators of the system know that this is enabled and the danger of putting in scope a RDP window with sensitive text in the clipboard so as to not store sensitive information in systems. It is not recommended to enable this capture on client machines do to the risk of unencrypted sensitive data being stored even if the folder are heavily permissioned with Access Control Lists. 

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

A sample configuration to capture all clipboard events:

```XML
<Sysmon schemaversion="4.40">
  <HashAlgorithms>sha1</HashAlgorithms>
  <CheckRevocation />
  <CaptureClipboard />
  <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <ClipboardChange onmatch="exclude">
         </ClipboardChange>
      </RuleGroup> 
  </EventFiltering>
</Sysmon>

```

This is an event of a user connecting to a VM using Hyper-V console that leverages RDP:

```XML
Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
  <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" /> 
  <EventID>24</EventID> 
  <Version>5</Version> 
  <Level>4</Level> 
  <Task>24</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8000000000000000</Keywords> 
  <TimeCreated SystemTime="2020-10-07T19:57:53.911567300Z" /> 
  <EventRecordID>92</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="2640" ThreadID="3884" /> 
  <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
  <Computer>SDDC01.acmelabs.pvt</Computer> 
  <Security UserID="S-1-5-18" /> 
  </System>
<EventData>
  <Data Name="RuleName">-</Data> 
  <Data Name="UtcTime">2020-10-07 19:57:53.908</Data> 
  <Data Name="ProcessGuid">{fcb91365-c386-5f7d-c100-000000000500}</Data> 
  <Data Name="ProcessId">108</Data> 
  <Data Name="Image">C:\Windows\System32\rdpclip.exe</Data> 
  <Data Name="Session">1</Data> 
  <Data Name="ClientInfo">user: acmelabs\Admin ip: FE80:0000:0000:0000:013E:52B8:0C83:3DE3 hostname: DESKTOP-LH0AJLB</Data> 
  <Data Name="Hashes">SHA1=292341BFA0C002051415142B99991871C53B3905,MD5=94B9F6FA8509AB6771F72304C0B3538B,SHA256=1AAE1F7AD5E7CB54F0302794430DFBB0CCCF6DA1F3C79DE1B17E8D367D7BF6C1,IMPHASH=00000000000000000000000000000000</Data> 
  <Data Name="Archived">true</Data> 
  </EventData>
  </Event>
```


