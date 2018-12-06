# SignClickOnce
#### This script signs your ClickOnce application with SignTool and then signs the manifest with Mage, using a provided PFX certificate or the thumbprint of one already installed into the user's certificate store.

## Overview
To code sign the ClickOnce application and the manifest, you need to use both SignTool and Mage.

SignTool doesn't like SHA1, Mage doesn't like SHA2.  What are we to do?

Thanks to the lovely guidance from:
[StackOverFlow](https://stackoverflow.com/questions/39538466/how-to-authenticode-sign-clickonce-deployment-with-an-ev-sha2-cert-and-avoid-un)
and combining that with
[another blerb][openSSLTip]

Built on the work of [Joe Pitt](https://www.joepitt.co.uk/Project/SignClickOnceApp/).


### Required Tools
* SignTool - _used to code sign the application executable and setup executables_
* Mage - _used to sign the application manifest and click once .application file_
* OpenSSL - _used to roundtrip PFX file before importing, based on [this][openSSLTip], to convert to a suitable 'CryptoAPI' version_
* CertUtil - _imports the certificate into the Cert://CurrentUser/My store_

### Required Permissions
* Administrator

### This script was designed to be integrated into an (Azure Devops) CI/CD pipeline.

* Either **PMXPath** and **PMXPassword** OR **SHA256CertThumbprint** are required for successful signing.  
 * If using **PMXPath** and **PMXPassword**, the certificate file will be installed and used.  If you are using a Hosted Agent, this is the best option.
 * If using **SHA256CertThumbprint**, the certificate must already be installed at Cert://CurrentUser/My.  If you are self-hosting a build agent, then the build agent account is where this needs to live.
 
* You can leverage Secure Files in Azure Dev Ops to supply the PMX file to the script, thus keeping it out of the repository.

### Steps for Azure DevOps

* Disable signing the ClickOnce manifest in your project files
* Verify build agent is running as Administrator
* Add SignClickOnceApp.ps1 to your repository or place in your build system at a known location.
* Add PMX Certificate to Secure Files in your DevOps project
* Add Download Secure File Task to your pipeline and configure to download certificate
* Add Powershell Task
* Call SignClickOnceApp with -PMXPath $(DOWNLOADSECUREFILE.SECUREFILEPATH) and other parameters, see script documentation _TODO add example invocations_
 * Profit

[openSSLTip]: http://maxprog.net.pl/windows/solved-visual-studio-invalid-provider-type-specified-cryptographicexception-when-trying-to-load-private-key-of-certificate/
