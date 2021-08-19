---
title: Use a Private Registry
description: Instructions for setting up Verrazzano using a private container registry
Weight: 5
draft: false
---


Verrazzano supports installation using a private Docker-compliant container registry.  This requires doing the following:

* Loading all required Verrazzano container images into your own registry and repository.
* Installing the Verrazzano platform operator with the private registry and repository used to load the images.

To obtain the required Verrazzano images and perform an installation from your private registry, 
you must do the following:

1. Locate and download the Verrazzano Zip file on the Oracle Software Delivery Cloud by doing the following:
   * Go to [Oracle Software Delivery Cloud](https://edelivery.oracle.com) in your browser and log in with your credentials.
   * In the dropdown next to the search bar, select "Download Package".
   * In the search bar, enter `Verrazzano Enterprise Container Platform` and click the `Search` button.
   * Click on the `DLP: Oracle Verrazzano Enterprise Edition 1.0` link.  This will add it to your download queue.
   * Click the `Continue` link on the top-left.
   * Accept the license agreement and click `Continue`
   * Download the file.
     * To download the Zip file directly, click the file link the list.
     * To download the Zip file using Oracle Download Manager, click `Download` and run the downloaded `Oracle Download Manager` executable.
2. Prepare to do the private registry install:
   * Unzip the Zip archive to a desired directory location.  There will be two files, a compressed TAR file containing the product 
     files and a checksum file. 
   * Go to the expanded archive directory.
   * (Optional) Validate the checksum and the TAR file match.  For example,
     ```
     $ shasum -c  verrazzano_1.0.0.tar.gz.sha256 
     verrazzano_1.0.0.tar.gz: OK
     ```
   * Expand the TAR file expanded from the Zip file.  For example, `tar xvf verrazzano_1.0.0.tar.gz`.
3. Load the product images into your private registry and install Verrazzano using the instructions in the `README.md` file that comes with the TAR file.
