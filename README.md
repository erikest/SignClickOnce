# SignClickOnce
A powershell script which takes PFX file and code signs both the code and the manifest correctly of a ClickOnce application.

## Overview
To code sign the ClickOnce application and the manifest, you need to use both SignTool and Mage.

SignTool doesn't like SHA1, Mage doesn't like SHA2.  What are we to do?

Thanks to the lovely guidance from:
[StackOverFlow](https://stackoverflow.com/questions/39538466/how-to-authenticode-sign-clickonce-deployment-with-an-ev-sha2-cert-and-avoid-un)
and combining that with
[Another blerb][openSSLTip]

This script builds on he work of [Joe Pitt](https://www.joepitt.co.uk/Project/SignClickOnceApp/).

signs with SignTool, then signs the manifest with Mage, using a provided PFX certificate or the thumbprint of one already installed into the user's certificate store.

### Required Tools
* SignTool - _used to code sign the application executable and setup executables_
* Mage - _used to sign the application manifest and click once .application file_
* OpenSSL - _used to roundtrip PFX file before importing, based on [this][openSSLTip], to convert to a suitable 'CryptoAPI' version_
* CertUtil - _imports the certificate into the Cert://CurrentUser/My store

### Required Permissions
* This script requires Administrator access.

### This script was designed to be integrated into an (Azure Devops) CI/CD pipeline.

* Either **PMXPath** and **PMXPassword** OR **SHA256CertThumbprint** are required for successful signing.  
 * If using **PMXPath** and **PMXPassword**, the certificate file will be installed and used.  If you are using a Hosted Agent, this is the best option.
 * If using **SHA256CertThumbprint**, the certificate must already be installed at Cert://CurrentUser/My.  If you are self-hosting a build agent, then the build agent account is where this needs to live.
 
* You can leverage Secure Files in Azure Dev Ops to supply the PMX file to the script, thus keeping it out of the repository.

[openSSLTip]: http://maxprog.net.pl/windows/solved-visual-studio-invalid-provider-type-specified-cryptographicexception-when-trying-to-load-private-key-of-certificate/
