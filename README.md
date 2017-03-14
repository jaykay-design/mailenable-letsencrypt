# JayKay.Mailenable

An service which renewes LetsEncrypt certificates for MailEEnable.

---


## Overview

This console app requires MailEnable to be installed.
* The app scanns all domains registered in MailEnable and verifies they have valid DNS entries for given subdomains (configurable)
* A website is created in the local IIS instance with bindings to all detected domains
* A certificate is requested at LetsEncrypt
* The certificate is stored in the local certificate store 
* All additional bindings created above are removed
* The old certificate ios removed
* The new certificate is bound to the IIS MEWebmail site
* All Mailenable services are restared
* A scheduled task is installed to run the app after x days (60 by default)

## Current State

* Mostly works but managing server certificates in MailEnable server is not documented anywhere so further testing needs to be done there.
* Scheduled task not verified


## Quick Start

* Build the app
* Adjust the Settings
** ServerIP (IP of the ME server)
** MainDomain (main domain of the ME server)
** StoragePath (where the LetsEncrypt certificates and config are stored)
** Email (email provided to LetsEncrypt)
** ExistingWebsiteTlsHost (the domain name where your MEWebmail is reachable)


*Please note, all documentation is still work-in-progress.*

*Please note, I take no responsibility for any MailEnable server downtimes caused by this app*