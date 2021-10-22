Image Loading
=============

Sysmon will log **EventID 7** for the loading of images (Components like
DLL, OCX..) by a given process. This filter can cause high CPU usage if
filtering is to open on desktop or terminal systems with lots of process
starting and stopping, because of this event is best targeted by
monitoring for specific libraries or combinations used by attackers.

The event fields are:

* **RuleName**: Name of rule that triggered the event.

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that loaded the image

* **ProcessId**: Process ID used by the OS to identify the process
    that loaded the image

* **Image**: File path of the process that loaded the image

* **ImageLoaded**: Path of the image loaded

* **FileVersion**: Version of the image loaded

* **Description**: Description of the image loaded

* **Product**: Product name the image loaded belongs to

* **Company**: Company name the image loaded belongs to

* **OriginalFileName**: OriginalFileName from the PE header, added on
    compilation

* **Hashes**: Full hash of the file with the algorithms in the
    HashType field

* **Signed**: State whether the image loaded is signed

* **Signature**: The signer name

* **SignatureStatus**: status of the signature

Example of libraries leveraged by attackers

```xml
<Sysmon schemaversion="4.22">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <ImageLoad onmatch="include">
                <!--Detect execution of HTA using the IE Javascript engine to bypass AMSI-->
                <!--Note: Rule placed before Windows Scriptingh to ensure it triggers on this on case any other component is used.-->
                <Rule groupRelation="and">
                    <ImageLoaded name="technique_id=T1170,technique_name=MSHTA with AMSI Bypass" condition="end with">jscript9.dll</ImageLoaded>
                    <Image condition="end with">mshta.exe</Image>
                </Rule>
                <!--Capture components used by malicious macros and scripts.-->
                <Rule groupRelation="or">
                    <ImageLoaded name="technique_id=T1064,technique_name=Windows Scripting Host Component" condition="end with">wshom.ocx</ImageLoaded>
                    <ImageLoaded condition="end with">scrrun.dll</ImageLoaded>
                    <ImageLoaded condition="end with">vbscript.dll</ImageLoaded>
                </Rule>
                <!--Check for loading of the PowerShell engine-->
                <Rule groupRelation="or">
                    <ImageLoaded name="technique_id=T1086,technique_name=PowerShell Engine" condition="end with">System.Management.Automation.ni.dll</ImageLoaded>
                    <ImageLoaded condition="end with">System.Management.Automation.dll</ImageLoaded>
                </Rule>
                <!--Detect the Squiblydoo technique-->
                <Rule groupRelation="or">
                    <ImageLoaded name="technique_id=T1117,technique_name=Regsvr32" condition="end with">scrobj.dll</ImageLoaded>
                </Rule>
            </ImageLoad>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
