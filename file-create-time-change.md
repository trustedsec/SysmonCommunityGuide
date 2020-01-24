File Create Time Change
=======================

File Creation Time Change **EventID 2** for the technique that modifies
the timestamps of a file (the modify, access, create, and change times)
This is done often to mimic files that are in the same folder to hide
dropped files or accessed files to prevent casual detection. Some
applications in their normal operation modify time stamps. A good
practice is to exclude those applications that normally change file
creation times like setup executables, Chrome, OneDrive and others. As a
minimum Users directory should be monitored.

The fields for the event:

* **RuleName**: Name of rule that triggered the event.

* **UtcTime**: Time in UTC when event was created

* **ProcessGuid**: Process Guid of the process that changed the file
    creation time

* **ProcessId**: Process ID used by the OS to identify the process
    changing the file creation time

* **Image**: File path of the process that changed the file creation
    time

* **TargetFilename**: Full path name of the file

* **CreationUtcTime**: New creation time of the file

* **PreviousCreationUtcTime**: Previous creation time of the file

Example:

```xml
<Sysmon schemaversion="4.22">
    <EventFiltering>
        <RuleGroup name="Include Filter for FileCreateTime" groupRelation="or">
            <FileCreateTime onmatch="include">
                <!-- Detect File Time changes on user files -->
                <Rule groupRelation="or">
                    <Image name="technique_id=T1099" condition="begin with">C:\Users</Image>
                </Rule>
            </FileCreateTime>
        </RuleGroup>

        <RuleGroup name="Exclude Filters for FileCreateTime" groupRelation="or">
            <FileCreateTime onmatch="exclude">
                <!-- Detect Dangerous File Type Creation -->
                <Rule groupRelation="or">
                    <Image condition="image">OneDrive.exe</Image> <!--OneDrive constantly changes file times-->
                    <Image condition="image">C:\Windows\system32\backgroundTaskHost.exe</Image>
                    <Image condition="contains">setup</Image> <!--Ignore setups-->
                    <Image condition="contains">install</Image> <!--Ignore setups-->
                    <Image condition="contains">Update\</Image> <!--Ignore setups-->
                    <Image condition="end with">redist.exe</Image> <!--Ignore setups-->
                    <Image condition="is">msiexec.exe</Image> <!--Ignore setups-->
                    <Image condition="is">TrustedInstaller.exe</Image> <!--Ignore setups-->
                </Rule>
            </FileCreateTime>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
