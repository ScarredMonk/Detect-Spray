# Detect-Spray
A C# tool that detects password spraying attempt by using Active Directory user attributes

This tool is written in C# which check for multiple bad password attempts from the user attributes.

First of all, I am fetching all the accounts using LDAP, that have value of badPwdCount > 0.

![image](https://user-images.githubusercontent.com/46210620/167267315-eb05ea6f-72c9-483a-a757-b59c4161c42d.png)

Then, I’m leveraging the Active Directory user attributes badPasswordTime and badPwdCount. I checked for the badPwdCount for multiple users and grouping them on basis of badPasswordTime attribute

When I’ll try password spraying for multiple users, it will get detected by the tool Detect-spray as shown in the screenshot:
![image](https://user-images.githubusercontent.com/46210620/167267340-e127d83d-3ad9-435f-8da9-6fb06f025cdc.png)

**Blogpost Link** - [https://rootdse.org/posts/monitoring-realtime-activedirectory-domain-scenarios](https://rootdse.org/posts/monitoring-realtime-activedirectory-domain-scenarios)
