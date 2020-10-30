<#
    .SYNOPSIS
    Show-AntiSpoof.ps1

    PowerShell based script that checks every accepted domain of Exchange and will 
    show the DNS configuration of SPF and DMARC for each domain using an external 
    DNS server. Alternatively you can request the same information on a specific 
    domain not necessarily configured as Accepted Domain.

    Dave Stork et. al.
    dmstork at stalpaert.nl
    https://dirteam.com/dave

    .LICENSE
    MIT License

    Copyright (c) 2018-2020 Dave Stork

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

    .VERSION
    Version 1.00    17 August 2018
    Version 1.01    20 August 2018
    Version 1.02    21 August 2018
    Version 1.03    12 December 2019
    Version 1.04    07 Februari 2020
    Version 1.10    30 October 2020

    Revision History
    ---------------------------------------------------------------------
    1.00    Private release
    1.01    Added support for custom DNS server at commandline
    1.02    Added support for custom domain at commandline, overrules checking Exchange
    1.03    Added MX records lookup
    1.04    Small bugfixes: Using Get-AcceptedDomains correctly, better DNS server check.
    1.1     Added more extensive DKIM checks for known selectors AND added parameter to check for a custom selector

    KNOWN LIMITATIONS:
    - Required to be run in Exchange PowerShell in order to check all of your accepted domains in one run.
    - Can't resolve the exact DKIM selector DNS record as that is a variable in most cases. 
      And due to security, most domain services don't allow complete zone transfers, 
      which you would need to find an unknown record. Since v1.1 you can add a customer record though.
    - Requires at last Windows Server 2012, or PowerShell v3.0 due to Resolve-DnsName
    - DNS check not working as intended, but should be no issue

    .LINK
    https://dirteam.com/dave

    .DESCRIPTION
    Run the script in Exchange PowerShell (remote or in your current environment) and a report will be show with 
    the current external SPF and DMARC configuration. Edit the variable if you require another default DNS server. 
    Without Exchange PowerShell, you can run the script and get the same information by explicitly stating a domain.

    .EXAMPLE
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

#>

# Add support for default parameters
[CmdletBinding()]

# Add parameters for target objects which will get postmaster address
Param(
    [switch]$TranscriptOn,
    [String]$DNSServer,
    [String]$Domain,
    [String]$Selector
)

#Initialize constants
$DNSServerDefault = "8.8.8.8"

If ($DNSServer -ne $null){
    Try {
        Resolve-DnsName -Server $DNSServer -Type MX -Name internet.nl -ErrorAction Stop
        Write-Output "Using IP $DNSServer as DNS server"
    } Catch {  
        $DefaultColor = $host.ui.RawUI.ForegroundColor
        $host.ui.RawUI.ForegroundColor = "Red"
        $ErrorMessage = $_.Exception.Message
        Write-Output "Error with DNS server, using default. $ErrorMessage"
        $host.ui.RawUI.ForegroundColor = $DefaultColor 
        $DNSServer = $DNSServerDefault
    }
}

# Start Transcript if requested
If ($TranscriptOn -eq $true) {
    # Defining logtime variable to be used in logging/default output folder
    $LogTime = Get-Date -Format "yyyyMMdd_hhmm_ss"

    # Initialize logging
    $TranscriptFile = "AntiSpoof_"+$LogTime+".txt"
    Start-Transcript -Path $TranscriptFile
}

# Overriding Exchange Accepted Domains
If ($Domain -eq ""){
    $AcceptedDomains = Get-AcceptedDomain 
}  Else {
    $AcceptedDomains = $Domain
}

ForEach ($AcceptedDomain in $AcceptedDomains) {
    Write-Output ""
    Write-Output "==============="
    Write-Output "Checking domain $AcceptedDomain"
    Write-Output "==============="

    # Check MX record
    Try {
        $MXRecords = Resolve-DnsName -Server $DNSServer -Type MX -Name $AcceptedDomain -DNSOnly -ErrorAction Stop
        $MXNumber = ($MXRecords).Count
        $MXcounter=1

        $DefaultColor = $host.ui.RawUI.ForegroundColor
        $host.ui.RawUI.ForegroundColor = "Magenta"
        Write-Output "Number of MX Records: $MXNumber"
        $host.ui.RawUI.ForegroundColor = $DefaultColor 

        ForEach ($MXRecord in $MXRecords) {
            $MXNameExchange = $MXRecord.NameExchange
            $MXPreference = $MXRecord.Preference
            $MXTTL = $MXRecord.TTL
           

            If ($null -ne $MXNameExchange) {
                $DefaultColor = $host.ui.RawUI.ForegroundColor
                $host.ui.RawUI.ForegroundColor = "Magenta"
                Write-Output "MX$MXCounter targets $MXNameExchange with preference $MXPreference and TTL $MXTTL"
                $host.ui.RawUI.ForegroundColor = $DefaultColor 
            }
            $MXcounter++
        }
    } Catch {
        $DefaultColor = $host.ui.RawUI.ForegroundColor
        $host.ui.RawUI.ForegroundColor = "Red"
        $ErrorMessage = $_.Exception.Message
        Write-Output "MX lookup failure: $ErrorMessage"
        $host.ui.RawUI.ForegroundColor = $DefaultColor     
    }

    # Check SPF record
    Try {
        $TXTRecords = Resolve-DnsName -Server $DNSServer -Type TXT -Name $AcceptedDomain -DNSOnly -ErrorAction Stop
        ForEach ($TXTRecord in $TXTRecords) {
            $TXTString = $TXTRecord.Strings
            
            If (($null -ne $TXTString) -and ($TXTString.StartsWith("v=spf1 "))) {
                $DefaultColor = $host.ui.RawUI.ForegroundColor
                $host.ui.RawUI.ForegroundColor = "Cyan"
                Write-Output "SPF: $TXTString"
                $host.ui.RawUI.ForegroundColor = $DefaultColor 
            } ElseIf ($null -eq $TXTString) {
                $DefaultColor = $host.ui.RawUI.ForegroundColor
                $host.ui.RawUI.ForegroundColor = "Red"
                Write-Output "$AcceptedDomain has no SPF record"
                $host.ui.RawUI.ForegroundColor = $DefaultColor 
            }
        }
    } Catch {
        $DefaultColor = $host.ui.RawUI.ForegroundColor
        $host.ui.RawUI.ForegroundColor = "Red"
        $ErrorMessage = $_.Exception.Message
        Write-Output "SPF lookup failure: $ErrorMessage"
        $host.ui.RawUI.ForegroundColor = $DefaultColor
    }
    
    # Check DMARC record
    Try {
        $DMARCDomain = "_dmarc."+$AcceptedDomain
        $DMARCRecord = Resolve-DnsName -Server $DNSServer -Type TXT -Name $DMARCDomain -Dnsonly -ErrorAction Stop
        $DMARCString = $DmarcRecord.Strings
        
        $DefaultColor = $host.ui.RawUI.ForegroundColor
        $host.ui.RawUI.ForegroundColor = "Green"
        Write-Output "DMARC: $DMARCString"
        $host.ui.RawUI.ForegroundColor = $DefaultColor
    } Catch {
        $ErrorMessage = $_.Exception.Message
        
        $DefaultColor = $host.ui.RawUI.ForegroundColor
        $host.ui.RawUI.ForegroundColor = "Red"
        Write-Output $ErrorMessage
        $host.ui.RawUI.ForegroundColor = $DefaultColor
    }

    # Check DKIM record
    Try {
        $DKIMDomain = "_domainkey."+$AcceptedDomain
        $DKIMResult = Resolve-DnsName -Server $DNSServer -Name $DKIMDomain -DnsOnly -ErrorAction Stop 
            
        $DefaultColor = $host.ui.RawUI.ForegroundColor
        $host.ui.RawUI.ForegroundColor = "Yellow"
        Write-Output "$DKIMDomain exists and may contain DKIM selectors"
        $host.ui.RawUI.ForegroundColor = $DefaultColor

    } Catch {
        $ErrorMessage = $_.Exception.Message
        
        $DefaultColor = $host.ui.RawUI.ForegroundColor
        $host.ui.RawUI.ForegroundColor = "Red"
        Write-Output $ErrorMessage
        $DKIMResult = $null
        Write-Output $DKIMResult
        $host.ui.RawUI.ForegroundColor = $DefaultColor
    }

    # Check-KnownDKIMSelectors
    Try {
        $DKIMDomainSelector = "selector1."+$DKIMDomain
        $DKIMDomainSelectorResult = Resolve-DnsName -Server $DNSServer -Name $DKIMDomainSelector -DnsOnly -ErrorAction Stop

        $DefaultColor = $host.ui.RawUI.ForegroundColor
        $host.ui.RawUI.ForegroundColor = "Yellow"
        Write-Output " Office 365 $DKIMDomainSelector exists"
        $host.ui.RawUI.ForegroundColor = $DefaultColor
    } Catch {
        Write-Output " No Office 365 Selector1 present"
    }
    Try {
        $DKIMDomainSelector = "selector2."+$DKIMDomain
        $DKIMDomainSelectorResult = Resolve-DnsName -Server $DNSServer -Name $DKIMDomainSelector -DnsOnly -ErrorAction Stop

        $DefaultColor = $host.ui.RawUI.ForegroundColor
        $host.ui.RawUI.ForegroundColor = "Yellow"
        Write-Output " Office 365 $DKIMDomainSelector exists"
        $host.ui.RawUI.ForegroundColor = $DefaultColor
    } Catch {
        Write-Output " No Office 365 Selector2 present"
    }

    Try {
        $DKIMDomainSelector = "k1."+$DKIMDomain
        $DKIMDomainSelectorResult = Resolve-DnsName -Server $DNSServer -Name $DKIMDomainSelector -DnsOnly -ErrorAction Stop

        $DefaultColor = $host.ui.RawUI.ForegroundColor
        $host.ui.RawUI.ForegroundColor = "Yellow"
        Write-Output " Mailchimp $DKIMDomainSelector exists"
        $host.ui.RawUI.ForegroundColor = $DefaultColor
    } Catch {
        Write-Output " No Mailchimp K1 selector present"
    }
    If ($Selector -ne ""){
        Try {
            $DKIMDomainSelector = $Selector+"."+$DKIMDomain
            $DKIMDomainSelectorResult = Resolve-DnsName -Server $DNSServer -Name $DKIMDomainSelector -DnsOnly -ErrorAction Stop

            $DefaultColor = $host.ui.RawUI.ForegroundColor
            $host.ui.RawUI.ForegroundColor = "Yellow"
            Write-Output " Custom selector $DKIMDomainSelector exists"
            $host.ui.RawUI.ForegroundColor = $DefaultColor
        } Catch {
            Write-Output " No custom selector $DKIMDomainSelector present"
        }
    }
}



# End Transcript
If ($TranscriptOn -eq $True) {
    Stop-Transcript
}