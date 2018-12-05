# SignClickOnce
A powershell script which takes PFX file and code signs both the code and the manifest correctly of a ClickOnce application.

## Overview
To code sign the ClickOnce application and the manifest, you need to use both SignTool and Mage.

SignTool doesn't like SHA1, Mage doesn't like SHA2.  What are we to do?

Thanks to the lovely guidance from:
[StackOverFlow](https://stackoverflow.com/questions/39538466/how-to-authenticode-sign-clickonce-deployment-with-an-ev-sha2-cert-and-avoid-un)
and combining that with
[Another blerb](http://maxprog.net.pl/windows/solved-visual-studio-invalid-provider-type-specified-cryptographicexception-when-trying-to-load-private-key-of-certificate/)

This script builds on he work of [Joe Pitt](https://www.joepitt.co.uk/Project/SignClickOnceApp/).

signs with SignTool, then signs the manifest with Mage, using a provided PFX certificate or the thumbprint of one already installed into the user's certificate store.

It was specifically modified from the original to be integrated into an Azure Devops CI/CD pipeline.

* Either PMXPath and PMXPassword OR SHA256CertThumbprint are required for successful signing.  
 * If using PMXPath and PMXPassword, the certificate file will be used to generate a PEM using open SSL and then exported back to a PFX which is then installed to Cert://CurrentUser/My using CertUtil
 * If using SHA256CertThumbprint, the certificate must already be installed at Cert://CurrentUser/My.  If you are self-hosting a build agent, then the build agent account is where this needs to live.
* You can leverage Secure Files in Azure Dev Ops to supply the PMX file to the script, thus keeping it out of the repository.
