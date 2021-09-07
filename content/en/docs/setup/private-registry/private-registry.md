---
title: Use a Private Registry
description: Instructions for setting up Verrazzano using a private container registry
Weight: 6
draft: false
---


You can install Verrazzano using a private Docker-compliant container registry. This requires the following:

* Loading all required Verrazzano container images into your own registry and repository.
* Installing the Verrazzano platform operator with the private registry and repository used to load the images.

To obtain the required Verrazzano images and install from your private registry, you must:

1. Download the Verrazzano ZIP file from the Oracle Software Delivery Cloud:
   * In your browser, go to [Oracle Software Delivery Cloud](https://edelivery.oracle.com) and log in with your credentials.
   * In the drop-down menu next to the search bar, select **Download Package**.
   * In the search bar, enter `Verrazzano Enterprise Container Platform` and click **Search**.
   * Select the `DLP: Oracle Verrazzano Enterprise Edition 1.0` link.  This will add it to your download queue.
   * Select the **Continue** link.
   * Accept the license agreement and click **Continue**.
   * Download the file:
     * To download the ZIP file directly, select the file link in the list.
     * To download the ZIP file using `Oracle Download Manager`, click **Download** and run the `Oracle Download Manager` executable.
2. Prepare to do the private registry install:
   * Unzip the ZIP archive to a desired directory location.  There will be two files, a compressed TAR file containing the product
     files and a checksum file.
   * Go to the expanded archive directory.
   * (Optional) Validate the checksum and the TAR file match.  For example,
     ```
     $ shasum -c  verrazzano_1.0.0.tar.gz.sha256
     verrazzano_1.0.0.tar.gz: OK
     ```
   * Expand the TAR file, for example, `tar xvf verrazzano_1.0.0.tar.gz`.
3. Load the product images into your private registry and install Verrazzano using the instructions in the `README.md`
   file that is packaged with the TAR file.
