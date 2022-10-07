---
title: Use a Private Registry
description: Instructions for setting up Verrazzano using a private container registry
Weight: 7
draft: false
---


Installing Verrazzano using a private Docker-compliant container registry requires the following:

* Loading all the required Verrazzano container images into your own registry and repository.
* Installing the Verrazzano platform operator with the private registry and repository used to load the images.

To obtain the required Verrazzano images and install from your private registry, you must:

1. Download the Verrazzano ZIP file:
    * Download the Verrazzano ZIP file from the Oracle Software Delivery Cloud for major or minor releases.

        a. In your browser, go to the [Oracle Software Delivery Cloud](https://edelivery.oracle.com) and log in with your credentials.

        b. In the drop-down menu preceding the search bar, select **All Categories**.

        c. In the search bar, enter `Verrazzano Enterprise Container Platform` and click **Search**.

        d. Select the `REL: Verrazzano Enterprise Edition {{<download_package_full_version>}}` link.  This will add it to your download queue.

        e. At the top of the page, select the **Continue** link.

        f. Review the Download Queue, then click **Continue**.

        g. Accept the license agreement and click **Continue**.

        h. Download the file:
        * To download the ZIP file directly, select the file link in the list.
        * To download the ZIP file using `Oracle Download Manager`, click **Download** and run the `Oracle Download Manager` executable.

    * Download the Verrazzano ZIP file from My Oracle Support for cumulative patches.

        a. In your browser, go to [My Oracle Support](https://support.oracle.com/) and log in with your credentials.

        b. Select the `Patches & Updates` tab.

        c. In the `Patch Search` panel, select the link `Product or Family (Advanced)`.

        d. In the search bar for `Product is`, enter `Oracle Verrazzano Enterprise Container Platform`.

        e. The previous step populates the available releases for Verrazzano in the drop-down menu `Release is`. Select the desired release(s) and click **Search**.

        f. A new panel with `Patch Advanced Search Results` will open listing all the patches for the release. Select the link for the desired patch, under the `Patch Name`.

        g. From the page providing details about the patch, click **Download**.

        h. Download the ZIP file by selecting the file link.

2. Prepare to do the private registry install:
   * Unzip the ZIP archive to a desired directory location.  There will be two files, a compressed TAR file containing the product
     files and a checksum file.
   * Go to the expanded archive directory.
   * (Optional) Validate the checksum and the TAR file match.  For example,
     ```
     $ shasum -c  verrazzano_{{<download_package_version>}}.tar.gz.sha256

     # Sample output
     verrazzano_{{<download_package_version>}}.tar.gz: OK
     ```
   * Expand the TAR file, for example, `tar xvf verrazzano_{{<download_package_version>}}.tar.gz`.
3. Load the product images into your private registry and install Verrazzano using the instructions in the `README.md`
   file that is packaged with the TAR file.

## Configuring access to an insecure private registry

A private Docker registry is called an [insecure registry](https://docs.docker.com/registry/insecure/) when it is configured for access using a self-signed certificate or over an unencrypted HTTP connection. Depending on the platform, there could be some additional configuration required for installing Verrazzano with an insecure registry.
 
For example, for the [Oracle Cloud Native Environment platform]({{< relref "/docs/setup/platforms/OLCNE/OLCNE.md" >}}), the insecure registries must be configured in `/etc/containers/registries.conf` as follows on the worker nodes:
 ```
 [registries]
    [registries.insecure]
      registries = ["insecure-registry-1:1001/registry1","insecure-registry-2:1001/registry2"]
 ```
