# Show-AntiSpoof
PowerShell based script that checks every accepted domain of Exchange and will show the DNS configuration of SPF and DMARC for each domain using an external DNS server. Alternatively you can request the same information on a specific domain not necessarily configured as Accepted Domain.

# Author
- Dave Stork
- dmstork at stalpaert.nl
- https://dirteam.com/dave
- https://twitter.com/dmstork

# License
MIT License Copyright (c) 2018-2020 Dave Stork

# Version
- Version 1.00    17 August 2018
- Version 1.01    20 August 2018
- Version 1.02    21 August 2018
- Version 1.03    12 December 2019
- Version 1.04    07 Februari 2020
- Version 1.1     30 October 2020

# Revision History
- 1.00    Private release
- 1.01    Added support for custom DNS server at commandline
- 1.02    Added support for custom domain at commandline, overrules checking Exchange
- 1.03    Added MX records lookup
- 1.04    Small bugfixes: Using Get-AcceptedDomains correctly, better DNS server check.
- 1.1     Added more extensive DKIM checks for known selectors AND added parameter to check for a custom selector

# Known Limitations
- Required to be run in Exchange PowerShell in order to check all of your accepted domains in one run.
- Can't resolve the exact DKIM selector DNS record as that is a variable in most cases. 
  And due to security, most domain services don't allow complete zone transfers, 
  which you would need to find an unknown record. Since v1.1 you can add a customer record though.
- Requires at last Windows Server 2012, or PowerShell v3.0 due to Resolve-DnsName
- DNS check not working as intended, but should be no issue

# Link
https://dirteam.com/dave

# Description
Run the script in Exchange PowerShell (remote or in your current environment) and a report will be show with the current external SPF 
and DMARC configuration. Edit the variable if you require another default DNS server. Without Exchange PowerShell, you can run the script and get the same information by explicitly stating a domain.

# Examples
    .\Show-AntiSpoof
    Checks all Exchange Accepted Domains 

    .\Show-AntiSpoof -TranscriptOn 
    Enables the creation of a transscript file in the same folder as where the script is run.

    .\Show-AntiSpoof -DNSServer 1.2.3.4
    Overrides the default DNS server (8.8.8.8) with one specified.
    
    .\Show-AntiSpoof -Domain contoso.com
    Overrides checking Accepted Domains from the Exchange environment and checks only the provides domain
    No Exchange PowerShell required when this is used.

    .\Show-AntiSpoof -Domain contoso.com -Selector Selector1
    Will check whether the specified domain has the DKIM selector specified by the -Selector parameter.
    