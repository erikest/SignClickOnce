<#
.SYNOPSIS 
    A PowerShell Script to correctly sign a ClickOnce Application using a SHA256 Certificate.
.DESCRIPTION 
    Microsoft ClickOnce Applications Signed with a SHA256 Certificate show as Unknown Publisher during installation, ClickOnce Applications signed with a SHA1 Certificate show an Unknown Publisher SmartScreen Warning once installed, this happens because:
     1) The ClickOnce installer only supports SHA1 certificates (not SHA256) without a specific override when signing, but,
     2) Microsoft has depreciated SHA1 for Authenticode Signing.
    
    This script signs the various parts of the ClickOnce Application so that both the ClickOnce Installer and SmartScreen are happy.

    It requires SignTool.exe, Mage.exe, CertUtil and OpenSSL

.PARAMETER ProjectName
    The Name of the ClickOnce Project Output, it is used to find the ..\Application Files\<ProjectName>_<Version> Folder
.PARAMETER PFXPath
    The full qualified path to a pkcs12 PFX file.  This file imported to Cert://CurrentUser/My and used for signing
.PARAMETER PFXPassword
    The password protecting the PFX file at PFXPath.
.PARAMETER SHA256CertThumbprint
    The Thumbprint of the SHA256 Code Signing Certificate, use instead of PFXPath and PFXPassword, if the certificate is already installed in the Cert://CurrentUser/My
.PARAMETER TimeStampingServer
    The Time Stamping Server to be used while signing.
.PARAMETER PublisherName
    The Publisher to be set on the ClickOnce files, should match the Publisher Name of the signing certificate.
.PARAMETER SignToolLocation
    The fully qualified path to the directory containing signtool.exe, if not provided, defaults to "C:\Program Files (x86)\Microsoft SDKs\ClickOnce\SignTool"
.PARAMETER MageLocation
    The fully qualified path to the directory containing mage.exe, if not provided, defaults to "C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.6.1 Tools"
.PARAMETER Verbose
    Writes verbose output.
.EXAMPLE
    SignClickOnceApp.ps1 -PFXPath "C:\Repos\MyProject\Certificates\MyCert.PFX" -PFXPassword "mypass" -ProjectName "MyProject" -TimeStampingServer "http://time.certum.pl/" -PublisherName "Awesome Software Inc."    
.NOTES 
    Authors  : Joe Pitt, Erik Taylor
    License : SignClickOnceApp by Joe Pitt is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License. To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-sa/4.0/.
.LINK 
    
#>
param (  
    [string]$ProjectName,
    [string]$PFXPath,
    [string]$PFXPassword,
    [string]$SHA256CertThumbprint, 
    [string]$TimeStampingServer,
    [string]$PublisherName,
	[string]$PublishPath,
	[string]$CryptoAPICert,
	[string]$SignToolLocation,
	[string]$MageLocation,
    [switch]$Verbose	
)

$oldverbose = $VerbosePreference
if($Verbose) 
{
	$VerbosePreference = "continue" 
}

#Check for Administrator role
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
	Write-Verbose "$($currentPrincipal.Identity.Name) is an Administrator!"
} else 
{
	Write-Error -Message "$($currentPrincipal.Identity.Name) is NOT an admin, booooo" '
                -RecommendedAction "Add $($currentPrincipal.Identity.Name) to an Administator role" '
                -ErrorId "0"
	exit 1
}

# Publish Path
if (!$PSBoundParameters.ContainsKey('publishPath')) {
	Write-Error -Message "publishPath required" -RecommendedAction "include the correct path the publish output" -ErrorId "3"		
	exit 3
} 

if (!(Test-Path $PublishPath)) {
    Write-Error -Message "Publish path, $($PublishPath), does not exist." -RecommendedAction "Verify the publish path is specified correctly"
}

# Application Files Path
if (Test-Path "$PublishPath\Application Files")
{
    Write-Verbose "Using '$PublishPath\Application Files' for Application Files Path"
    $AppFilesPath = "$PublishPath\Application Files"
}
else
{
    Write-Error -Message "Application Files path does not exist." -RecommendedAction "Check Project has been published to \publish and try again" -ErrorId "5" `
        -Category ObjectNotFound -CategoryActivity "Testing Application Files Path" -CategoryReason "The Application Files path was not found" `
        -CategoryTargetName "$PublishPath\Application Files" -CategoryTargetType "Directory"
    exit 5
}

# Target Path
$TargetPaths = Get-ChildItem -Path $AppFilesPath -Filter "${ProjectName}_*" -Directory | Sort-Object -Descending 
if ($TargetPaths.Count -gt 0)
{
    $TargetPath = $TargetPaths[0].FullName
    Write-Verbose "Using '$TargetPath' for Target Path"
}
else
{
    Write-Error -Message "No versions." -RecommendedAction "Check Project has been published to \publish and try again" -ErrorId "6" `
        -Category ObjectNotFound -CategoryActivity "Searching for published version path" -CategoryReason "Application has not been published yet" `
        -CategoryTargetName "$AppFilesPath\${ProjectName}_*" -CategoryTargetType "Directory"
    exit 6
}

#Import Certificate
$Cert = $null
$SecurePassword = $null
if ($PSBoundParameters.ContainsKey('PFXPath')) {
    if (Test-Path $PFXPath) {
		$tempPem = "temp.pem"
		$pass = "pass:$($PFXPassword)"	
		$cryptoAPIPFXPath = "$($env:temp)\crypto-api.pfx"
		
        Write-Verbose "openssl pkcs12 -in '$PFXPath' -out '$tempPem' -password '$pass' -passout '$pass'"
		openssl pkcs12 -in "$PFXPath" -out "$tempPem" -password "$pass" -passout "$pass"
		Write-Verbose "openssl pkcs12 -export -in '$tempPem' -out '$cryptoAPIPFXPath' -password '$pass' -passin '$pass'"
		openssl pkcs12 -export -in "$tempPem" -out "$cryptoAPIPFXPath" -password "$pass" -passin "$pass"

		$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $Cert.Import($cryptoAPIPFXPath, $PFXPassword, "UserKeySet") 
        $SHA256CertThumbprint = $Cert.Thumbprint
		certutil -f -p "$PFXPassword" -importPfx -user My "$cryptoAPIPFXPath" NoRoot
        Write-Verbose "$($Cert.Thumbprint) Certificate Imported"
		
    } else {
        Write-Error -Message "Cannot find PFX file." -RecommendedAction "Check the PFXPath parameter and verify it is correct."
    }
}

# SHA256 Certificate
if ("$SHA256CertThumbprint" -notmatch "^[0-9A-Fa-f]{40}$")
{
    Write-Error -Message "SHA256 Thumbprint Malformed" -RecommendedAction "Check the thumbprint and try again" -ErrorId "9" `
        -Category InvalidArgument -CategoryActivity "Verifying Thumbprint Format" -CategoryReason "Thumbprint is not 40 Char Base64 String" `
        -CategoryTargetName "$SHA256CertThumbprint" -CategoryTargetType "Base64String"
    exit 9
}

if ($Cert -eq $null) {
    $SHA256Found = Get-ChildItem -Path Cert:\CurrentUser\My | where {$_.Thumbprint -eq "$SHA256CertThumbprint"} | Measure-Object
    if ($SHA256Found.Count -eq 0)
    {
        Write-Error -Message "SHA256 Certificate Not Found" -RecommendedAction "Check the thumbprint and try again" -ErrorId "10" `
            -Category ObjectNotFound -CategoryActivity "Searching for certificate" -CategoryReason "Certificate with Thumbprint not found" `
            -CategoryTargetName "$SHA256CertThumbprint" -CategoryTargetType "Base64String"
        exit 10
    } else {
	    Write-Verbose "Certificate with thumbprint $SHA256CertThumbprint Found!"
    }
}

# TimeStamping Server
if(!$PSBoundParameters.ContainsKey('TimeStampingServer'))
{
    $TimeStampingServer = Read-Host "TimeStamping Server URL"
}
if ("$TimeStampingServer" -notmatch "^http(s)?:\/\/[A-Za-z0-9-._~:/?#[\]@!$&'()*+,;=]+$")
{
    Write-Error -Message "TimeStamping Server URL Malformed" -RecommendedAction "Check the TimeStamp URL and try again" -ErrorId "11" `
        -Category InvalidArgument -CategoryActivity "Verifying TimeStamping URL" -CategoryReason "TimeStamping URL is not a valid URL" `
        -CategoryTargetName "$TimeStampingServer" -CategoryTargetType "URL"
    exit 11
}

if (!$PSBoundParameters.ContainsKey('SignToolLocation')) {    
    $SignToolLocation = "C:\Program Files (x86)\Microsoft SDKs\ClickOnce\SignTool"
    Write-Verbose "SignToolLocation not specified, defaulting to $SignToolLocation"
}

if (Test-Path "$SignToolLocation\signtool.exe") {
    Write-Verbose "SignTool found at $SignToolLocation" 
} else {
    Write-Error -Message "Sign Tool could not be found at $SignToolLocation" -RecommendedAction "Verify and try again with the correct path"
    exit 12
}

if (!$PSBoundParameters.ContainsKey('MageLocation')) {    
    $MageLocation = "C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.6.1 Tools"
    Write-Verbose "MageLocation not specified, defaulting to $MageLocation"
}

if (Test-Path "$MageLocation\mage.exe") {
    Write-Verbose "Mage found at $MageLocation" 
} else {
    Write-Error -Message "Mage could not be found at $MageLocation" -RecommendedAction "Verify and try again with the correct path"
    exit 13
}

# Sign setup.exe and application.exe with SHA256 Cert
Write-Verbose "Signing '$PublishPath\Setup.exe' (SHA256)"
Start-Process "$SignToolLocation\signtool.exe" -ArgumentList "sign /fd SHA256 /td SHA256 /tr $TimeStampingServer /sha1 $SHA256CertThumbprint `"$PublishPath\Setup.exe`"" -Wait -NoNewWindow
Write-Verbose "Signing '$TargetPath\$ProjectName.exe.deploy' (SHA256)"
Start-Process "$SignToolLocation\signtool.exe" -ArgumentList "sign /fd SHA256 /td SHA256 /tr $TimeStampingServer /sha1 $SHA256CertThumbprint `"$TargetPath\$ProjectName.exe.deploy`"" -Wait -NoNewWindow

# Remove .deploy extensions
Write-Verbose "Removing .deploy extensions"
Get-ChildItem "$TargetPath\*.deploy" -Recurse | Rename-Item -NewName { $_.Name -replace '\.deploy','' } 

# Sign Manifests with SHA256 Cert
Write-Verbose "Signing '$TargetPath\$ProjectName.exe.manifest' (SHA256)"
Start-Process "$MageLocation\mage.exe" -ArgumentList "-update `"$TargetPath\$ProjectName.exe.manifest`" -Algorithm sha256RSA -ch $SHA256CertThumbprint -if `"Logo.ico`" -ti `"$TimeStampingServer`"" -Wait -NoNewWindow
#Write-Verbose "Signing '$TargetPath\$ProjectName.application' (SHA256)"
#Start-Process "$MageLocation\mage.exe" -ArgumentList "-update `"$TargetPath\$ProjectName.application`" -Algorithm sha256RSA -ch $SHA256CertThumbprint -appManifest `"$TargetPath\$ProjectName.exe.manifest`" -pub `"$PublisherName`" -ti `"$TimeStampingServer`"" -Wait -NoNewWindow
Write-Verbose "Signing '$PublishPath\$ProjectName.application' (SHA256)"
Start-Process "$MageLocation\mage.exe" -ArgumentList "-update `"$PublishPath\$ProjectName.application`" -Algorithm sha256RSA -ch $SHA256CertThumbprint -appManifest `"$TargetPath\$ProjectName.exe.manifest`" -pub `"$PublisherName`" -ti `"$TimeStampingServer`"" -Wait -NoNewWindow

# Read .deply extensions
Write-Verbose "Re-adding .deploy extensions"
Get-ChildItem -Path "$TargetPath\*"  -Recurse | Where-Object {!$_.PSIsContainer -and $_.Name -notlike "*.manifest" -and $_.Name -notlike "*.application"} | Rename-Item -NewName {$_.Name + ".deploy"}

#Delete Certificate
certutil -delstore My "$PublisherName" #says it completes, but doesn't actually remove the certificate.  

# SIG # Begin signature block
# MIIW8AYJKoZIhvcNAQcCoIIW4TCCFt0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCBgN0L/BuwQ+pI
# l2abCcVNT3AGDtVIJQLTj5Oy/WNxEqCCCuowggTeMIIDxqADAgECAhBrMmoPAyjT
# eh1TC/0jvUjiMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlBMMSIwIAYDVQQK
# ExlVbml6ZXRvIFRlY2hub2xvZ2llcyBTLkEuMScwJQYDVQQLEx5DZXJ0dW0gQ2Vy
# dGlmaWNhdGlvbiBBdXRob3JpdHkxIjAgBgNVBAMTGUNlcnR1bSBUcnVzdGVkIE5l
# dHdvcmsgQ0EwHhcNMTUxMDI5MTEzMDI5WhcNMjcwNjA5MTEzMDI5WjCBgDELMAkG
# A1UEBhMCUEwxIjAgBgNVBAoMGVVuaXpldG8gVGVjaG5vbG9naWVzIFMuQS4xJzAl
# BgNVBAsMHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEkMCIGA1UEAwwb
# Q2VydHVtIENvZGUgU2lnbmluZyBDQSBTSEEyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAt9uo2MjjvNrag7q5v9bVV1NBt0C6FwxEldTpZjt/tL6Qo5QJ
# pa0hIBeARrRDJj6OSxpk7A5AMkP8gp//Si3qlN1aETaLYe/sFtRJA9jnXcNlW/JO
# CyvDwVP6QC3CqzMkBYFwfsiHTJ/RgMIYew4UvU4DQ8soSLAt5jbfGz2Lw4ydN57h
# BtclUN95Pdq3X+tGvnYoNrgCAEYD0DQbeLQox1HHyJU/bo2JGNxJ8cIPGvSBgcdt
# 1AR3xSGjLlP5d8/cqZvDweXVZy8xvMDCaJxKluUf8fNINQ725LHF74eAOuKADDSd
# +hRkceQcoaqyzwCn4zdy+UCtniiVAg3OkONbxQIDAQABo4IBUzCCAU8wDwYDVR0T
# AQH/BAUwAwEB/zAdBgNVHQ4EFgQUwHu0yLduVqcJSJr4ck/X1yQsNj4wHwYDVR0j
# BBgwFoAUCHbNywf/JPbFze27kLzihDdGdfcwDgYDVR0PAQH/BAQDAgEGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9jcmwuY2Vy
# dHVtLnBsL2N0bmNhLmNybDBrBggrBgEFBQcBAQRfMF0wKAYIKwYBBQUHMAGGHGh0
# dHA6Ly9zdWJjYS5vY3NwLWNlcnR1bS5jb20wMQYIKwYBBQUHMAKGJWh0dHA6Ly9y
# ZXBvc2l0b3J5LmNlcnR1bS5wbC9jdG5jYS5jZXIwOQYDVR0gBDIwMDAuBgRVHSAA
# MCYwJAYIKwYBBQUHAgEWGGh0dHA6Ly93d3cuY2VydHVtLnBsL0NQUzANBgkqhkiG
# 9w0BAQsFAAOCAQEAquU/dlQCTHAOKak5lgYPMbcL8aaLUvsQj09CW4y9MSMBZp3o
# KaFNw1D69/hFDh2C1/z+pjIEc/1x7MyID6OSCMWBWAL9C2k7zbg/ST3QjRwTFGgu
# mw2arbAZ4p7SfDl3iG8j/XuE/ERttbprcJJVbJSx2Df9qVkdtGOy3BPNeI4lNcGa
# jzeELtRFzOP1zI1zqOM6beeVlHBXkVC2be9zck8vAodg4uoioe0+/dGLZo0ucm1P
# xl017pOomNJnaunaGc0Cg/l0/F96GAQoHt0iMzt2bEcFXdVS/g66dvODEMduMF+n
# YMf6dCcxmyiD7SGKG/EjUoTtlbytOqWjQgGdvDCCBgQwggTsoAMCAQICEAeW39Eb
# ZqxDRi/B/bmNWN0wDQYJKoZIhvcNAQELBQAwgYAxCzAJBgNVBAYTAlBMMSIwIAYD
# VQQKDBlVbml6ZXRvIFRlY2hub2xvZ2llcyBTLkEuMScwJQYDVQQLDB5DZXJ0dW0g
# Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkxJDAiBgNVBAMMG0NlcnR1bSBDb2RlIFNp
# Z25pbmcgQ0EgU0hBMjAeFw0xNjExMTExNjAxNTNaFw0xNzExMDcwMDAwMDBaMH4x
# CzAJBgNVBAYTAkdCMR4wHAYDVQQKDBVPcGVuIFNvdXJjZSBEZXZlbG9wZXIxKDAm
# BgNVBAMMH09wZW4gU291cmNlIERldmVsb3BlciwgSm9lIFBpdHQxJTAjBgkqhkiG
# 9w0BCQEWFkpvZS5QaXR0QGpvZXBpdHQuY28udWswggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQDej5psU0ib5RxOm+HyYQAVhQ3QY42KkjQKYlKvCXZy4Mq+
# yoy7P7vexjF1Tcf7qt0ks0z3Yq4TBn4AzPXgJP854jqD0fFvNCZf9/J+Jb/nju8g
# EyO6hG55XSLCd0N6uIg6WFLXiY2ZNoM4RDGG5C/A2NMuG5rbOl6wjI+5zIhbAJ3r
# wBrEZ1w6775+yGoa62PBWilvDxP4E7rltp+vjJ/tvJKnv9lgi+yHkTZdPH+RPCHZ
# hiDJs5YyJpHu/kKyuy4eSWdj8a6uAD9cZj/A0LJV2EWpGB0DDDSCn93su2enqsU/
# LbQZr1vGhZoWzolDUeyCOL4q9bFx2v20h+bML0OVAgMBAAGjggJ5MIICdTAMBgNV
# HRMBAf8EAjAAMDIGA1UdHwQrMCkwJ6AloCOGIWh0dHA6Ly9jcmwuY2VydHVtLnBs
# L2NzY2FzaGEyLmNybDBxBggrBgEFBQcBAQRlMGMwKwYIKwYBBQUHMAGGH2h0dHA6
# Ly9jc2Nhc2hhMi5vY3NwLWNlcnR1bS5jb20wNAYIKwYBBQUHMAKGKGh0dHA6Ly9y
# ZXBvc2l0b3J5LmNlcnR1bS5wbC9jc2Nhc2hhMi5jZXIwHwYDVR0jBBgwFoAUwHu0
# yLduVqcJSJr4ck/X1yQsNj4wHQYDVR0OBBYEFC6PUBlklhUPmgd/CeZkikgCyORM
# MB0GA1UdEgQWMBSBEmNzY2FzaGEyQGNlcnR1bS5wbDAOBgNVHQ8BAf8EBAMCB4Aw
# ggE4BgNVHSAEggEvMIIBKzCCAScGBWeBDAEEMIIBHDAlBggrBgEFBQcCARYZaHR0
# cHM6Ly93d3cuY2VydHVtLnBsL0NQUzCB8gYIKwYBBQUHAgIwgeUwIBYZVW5pemV0
# byBUZWNobm9sb2dpZXMgUy5BLjADAgEBGoHAVXNhZ2Ugb2YgdGhpcyBjZXJ0aWZp
# Y2F0ZSBpcyBzdHJpY3RseSBzdWJqZWN0ZWQgdG8gdGhlIENFUlRVTSBDZXJ0aWZp
# Y2F0aW9uIFByYWN0aWNlIFN0YXRlbWVudCAoQ1BTKSBpbmNvcnBvcmF0ZWQgYnkg
# cmVmZXJlbmNlIGhlcmVpbiBhbmQgaW4gdGhlIHJlcG9zaXRvcnkgYXQgaHR0cHM6
# Ly93d3cuY2VydHVtLnBsL3JlcG9zaXRvcnkuMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MA0GCSqGSIb3DQEBCwUAA4IBAQCPPU7Sq+aJnEQ+VXq1GiDhng7Eg6dlsZXFu9W8
# NWv+nDk4mXL5kQvjeaPMViI33ROw67AG2rAD0k/3+C5ael5YcRxkS/7/xefPwvJL
# WrWF/DJTahiceIKKoUpkgdq3koZFiV0lAlA4DuMscY0qNZQC41cyDsWxWn7mA5fm
# Vie0/uKhwElGM4tk5lrlo2X6Yl41HSlMySlX8cQrAJyEr7Ne4lgteI7u9UIlWJmh
# exOGp5CAam+WcWwObfO11cXgHxsFM+OGiU1siCzIq1g4Y6GD57/aUM9UWse50bW8
# PmG042gi+fqbLPFKrc4SPR21OYiegwJjQU26uBZu8TRrDyrYMYILXDCCC1gCAQEw
# gZUwgYAxCzAJBgNVBAYTAlBMMSIwIAYDVQQKDBlVbml6ZXRvIFRlY2hub2xvZ2ll
# cyBTLkEuMScwJQYDVQQLDB5DZXJ0dW0gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
# JDAiBgNVBAMMG0NlcnR1bSBDb2RlIFNpZ25pbmcgQ0EgU0hBMgIQB5bf0RtmrENG
# L8H9uY1Y3TANBglghkgBZQMEAgEFAKB8MBAGCisGAQQBgjcCAQwxAjAAMBkGCSqG
# SIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3
# AgEVMC8GCSqGSIb3DQEJBDEiBCCdrwRkPF3yXaOqUNhhbdwpUc0A1eePDMeT2AwJ
# fQHSCTANBgkqhkiG9w0BAQEFAASCAQA79gxUCT57AmevFJoqRixPGFSPSUigWcTA
# TNaBn+NxDYhsaAaeemrqpTCnpu/AGCioXHBtpQy0s8iOlyw6VZL7Lu1x7iemUE11
# pkp9oL9Q33l6XJfl4QDa44tjql3dHcGUVnzn9tySz0eovzvGTggbH3YKPjWAzhW5
# /IqioPciKaDc0B9L2kyoCjj1TjWO034YPAZ6u+tjNsVHLhpa2v0eHtV8ciLrggMF
# GUIC7S1AuB+jI5/i9EpWVjOXorn3bhPyv/UYCMc2Rc4rXRHkF/JSknyxdd+sOmCW
# +jBvgyuiwJ0R2YbYar+aSfvYMjyvdbHXD7Ynl4L9Ae1xPGUB3wKLoYIJGTCCCRUG
# CisGAQQBgjcDAwExggkFMIIJAQYJKoZIhvcNAQcCoIII8jCCCO4CAQMxDTALBglg
# hkgBZQMEAgEwgfUGCyqGSIb3DQEJEAEEoIHlBIHiMIHfAgEBBgsqhGgBhvZ3AgUB
# CzAxMA0GCWCGSAFlAwQCAQUABCA0AIW8CHBkOJ1ZnWI6jydkd+IwnoS3NLqSb3uW
# W5nynwIHA41+qk//bBgPMjAxNzAxMTYxODUyNDRaMAMCAQGge6R5MHcxCzAJBgNV
# BAYTAlBMMSIwIAYDVQQKDBlVbml6ZXRvIFRlY2hub2xvZ2llcyBTLkEuMScwJQYD
# VQQLDB5DZXJ0dW0gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxGzAZBgNVBAMMEkNl
# cnR1bSBFViBUU0EgU0hBMqCCBOAwggTcMIIDxKADAgECAhEA/mfk8Vok48YNVHyg
# IMJ2cDANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5p
# emV0byBUZWNobm9sb2dpZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmlj
# YXRpb24gQXV0aG9yaXR5MSIwIAYDVQQDExlDZXJ0dW0gVHJ1c3RlZCBOZXR3b3Jr
# IENBMB4XDTE2MDMwODEzMTA0M1oXDTI3MDUzMDEzMTA0M1owdzELMAkGA1UEBhMC
# UEwxIjAgBgNVBAoMGVVuaXpldG8gVGVjaG5vbG9naWVzIFMuQS4xJzAlBgNVBAsM
# HkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEbMBkGA1UEAwwSQ2VydHVt
# IEVWIFRTQSBTSEEyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv1eL
# vJEzWi5XMX8lV/RbU1hqJarogSDMDR1HOHAaoxY3nbdEdLUagST69RhKOEsLoLrF
# vzRv6oz1nUIa0DGoVt2oJQ60PCXFrMbLXOOAkuqjry0AQEB80kEoHysI6FHQXYlw
# ImxpdtB2EjwuSwcpJun4AeHQ5Sj2JMMV+qaQhHSFXIMsDsTaeEmUah0khpfpIsDG
# DDXgdDKqPbsB2H7ME0wgx5UtSfbxLRe8xin3+FV2nH0V3N7hQpWTYJn3Q8WUQiG9
# mKwcs2bc/XhgRD89xJVpZ+5hy9rQueZ296E/BPTT53GvIQJeEdpTpKa1kXjZkBFb
# tKHup24K2XOkOAVSIwIDAQABo4IBWjCCAVYwDAYDVR0TAQH/BAIwADAdBgNVHQ4E
# FgQU8zXKjkYIDTmN30HHM25k5BY7mCswHwYDVR0jBBgwFoAUCHbNywf/JPbFze27
# kLzihDdGdfcwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMI
# MC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9jcmwuY2VydHVtLnBsL2N0bmNhLmNy
# bDBrBggrBgEFBQcBAQRfMF0wKAYIKwYBBQUHMAGGHGh0dHA6Ly9zdWJjYS5vY3Nw
# LWNlcnR1bS5jb20wMQYIKwYBBQUHMAKGJWh0dHA6Ly9yZXBvc2l0b3J5LmNlcnR1
# bS5wbC9jdG5jYS5jZXIwQAYDVR0gBDkwNzA1BgsqhGgBhvZ3AgUBCzAmMCQGCCsG
# AQUFBwIBFhhodHRwOi8vd3d3LmNlcnR1bS5wbC9DUFMwDQYJKoZIhvcNAQELBQAD
# ggEBAMp05Di9MskaPPorWMVXLTVTC5DeLQWy8TMyQBuW/yJFhzmuDPAZzsHQMkQa
# MwyA6z0zK3x5NE7GgUQ0WFa6OQ3w5LMDrDd1wHrrt0D2mvx+gG2ptFWJPZhIylb0
# VaQu6eHTfrU4kZXEz7umHnVrVlCbbqfr0ZzhcSDV1aZYq+HlKV2B8QS15BtkQqE4
# cT17c2TGadQiMJawJMMCWxGoPDRie2dn4UaGV3zoip+Quzhb2bWJ6gMo2423Wwdt
# MruHf9wmzi5e6Nar2+am0OIZAhL5oNs+nVLETL1Xhe147cGWRM1GsM5l1VdyOiTG
# EOGwc8SPWoOs9sZylPlyd/8B1SExggL8MIIC+AIBATCBkzB+MQswCQYDVQQGEwJQ
# TDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dpZXMgUy5BLjEnMCUGA1UECxMe
# Q2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MSIwIAYDVQQDExlDZXJ0dW0g
# VHJ1c3RlZCBOZXR3b3JrIENBAhEA/mfk8Vok48YNVHygIMJ2cDANBglghkgBZQME
# AgEFAKCCATkwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJ
# BTEPFw0xNzAxMTYxODUyNDRaMC8GCSqGSIb3DQEJBDEiBCA9FomBrMkgw8rDr7lG
# N4CsVQizJ0azKqt6nCMibvZ9AjCBywYLKoZIhvcNAQkQAgwxgbswgbgwgbUwgbIE
# FE+NTEgGSUJq74uG1NX8eTLnFC2FMIGZMIGDpIGAMH4xCzAJBgNVBAYTAlBMMSIw
# IAYDVQQKExlVbml6ZXRvIFRlY2hub2xvZ2llcyBTLkEuMScwJQYDVQQLEx5DZXJ0
# dW0gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxIjAgBgNVBAMTGUNlcnR1bSBUcnVz
# dGVkIE5ldHdvcmsgQ0ECEQD+Z+TxWiTjxg1UfKAgwnZwMA0GCSqGSIb3DQEBAQUA
# BIIBAL2dUO56Z79K3ayQHnbYO5766kI2TD065kI64S7ssdcy3tqxjUnnEaivef31
# Fv0mffwCpElRNx/x01p4RddyyJJYh7ovRTVkFAkuVrusp3YpF3kX0kZ15Br3bVrZ
# eo6HOmHCmgDu+M0ygIlqkVS45pquyFcx7E28V/g00wKevb0kAiYEIZOySG6922E2
# kntS8tQlpx2rUuqomBXYNz2y7szwuOwbKkItHaQ+vVE4pLTMXhquRgd29JvQTHVi
# iVxg069S0qZtQkTI3qkjkv0pV7Y/Gs4yyN8gx1aO47otg2CnFWTzeh3f461rXIcw
# SW95GyNP4k4v2UURkueGBBtKp0k=
# SIG # End signature block
