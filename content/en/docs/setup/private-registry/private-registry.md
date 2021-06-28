---
title: Using a Private Registry
description: Instructions for setting up Verrazzano using a private container registry
linkTitle: Using a Private Registry
Weight: 5
draft: false
---

### Using a Private Registry with Verrazzano

Verrazzano supports being able to install from a private Docker-compliant container registry, which requires:

* Loading all required Verrazzano container images into your own registry and repository.
* Installing the Verrazzano Platform Operator with the private registry and repository used to load the images.

To load the required Verrazzano images, and prepare for install from your private registry you must do the following:

* Download the tar file containing the full set of images for the Verrazzano release from the [Oracle Software Download Center](https://www.oracle.com/downloads/).
* Extract all files from the tarball locally and follow instructions in the [README](https://github.com/verrazzano/verrazzano/blob/master/tools/scripts/README.md)
  file that comes with the TAR file.
  
