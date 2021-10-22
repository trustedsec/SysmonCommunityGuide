Driver Loading
==============

Sysmon will log EventID 6 for the loading of drivers. Drivers have been used by attackers for the installation of rootkits or to run tooling that needs to run at the kernel level. Mimikatz is known to use a driver to perform tasks to query and modify the UFI to bypass process protections.

Sysmon will provide code signing information allowing filtering on those fields. Sysmon can also check if a certificate that signed the driver has been revoked.

A recommended action for this event is to filter on the **Signature** and **SignatureStatus** fields and exclude known drivers. The main reason to filter on both fields is that many of the attacks steal certificates that are later revoked. By confirming that the **SignatureStatus** is valid, we can find easier drivers signed by a vendor who has been forced to revoke that specific signing certificate.

The process for Signature values should be a constant one.


![process](./media/image48.png)

Initial rule for collecting DriverLoad events

```xml
<Sysmon schemaversion="4.22">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <!--Filter none driver default rule events-->
            <ProcessCreate onmatch = "include">
            </ProcessCreate>
            <ProcessTerminate onmatch = "include">
            </ProcessTerminate>
            <FileCreate onmatch = "include">
            </FileCreate>
            <FileCreateTime onmatch = "include">
            </FileCreateTime>

            <!--Include all driver events-->
            <DriverLoad onmatch="exclude">
            </DriverLoad>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```

Collect unique Signature field values for building filters

The event fields are:

* **RuleName**: Name of rule that triggered the event.

* **UtcTime**: Time in UTC when event was created

* **ImageLoaded**: File path of the driver loaded

* **Hashes**: Hashes captured by Sysmon driver

* **Signed**: Is the driver loaded signed

* **Signature**: Signer name of the driver

* **SignatureStatus**: Status of the signature

Example filtering out drivers signed by Microsoft, Intel and VMware for
a VDI environment

```xml
<Sysmon schemaversion="4.22">
    <CheckRevocation/>
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <DriverLoad onmatch="exclude">
                <!--Exclude signed Microsoft drivers-->
                <Rule groupRelation="and">
                    <Signature condition="contains">Microsoft</Signature>
                    <SignatureStatus condition="is">Valid</SignatureStatus>
                </Rule>
                <!--Exclude signed Inter drivers-->
                <Rule groupRelation="and">
                    <Signature condition="begin with">Intel </Signature>
                    <SignatureStatus condition="is">Valid</SignatureStatus>
                </Rule>
                <!--Exclude signed VMware drivers-->
                <Rule groupRelation="and">
                    <Signature condition="begin with">VMware</Signature>
                    <SignatureStatus condition="is">Valid</SignatureStatus>
                </Rule>
            </DriverLoad>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
```
