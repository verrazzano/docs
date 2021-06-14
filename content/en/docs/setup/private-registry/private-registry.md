---
title: Using a Private Registry
description: Instructions for setting up Verrazzano using a private container registry
linkTitle: Using a Private Registry
Weight: 5
draft: true
---

### Using a Private Registry with Verrazzano

Verrazzano supports being able to install from a private Docker-compliant container registry, which requires:

* Loading all required Verrazzano container images into your own registry and repository.
* Installing the Verrazzano Platform Operator with the private registry and repository used to load the images.

To load the required Verrazzano images, you must do the following:

* Download the full set of images for the Verrazzano release from the [Oracle Software Download Center](https://www.oracle.com/downloads/).
* Extract all files from the tarball locally and follow instructions in the README file that came with the tar file.


  
