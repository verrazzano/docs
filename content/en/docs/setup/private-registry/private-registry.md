---
title: Use a Private Registry
description: Instructions for setting up Verrazzano using a private container registry
Weight: 8
draft: false
---

{{ if .Site.Params.Bundle "Lite" }}
    Blahdiblah
{{ end if }}

You can install Verrazzano using a private Docker-compliant container registry. This requires the following:

* Loading all required Verrazzano container images into your own registry and repository.
* Installing the Verrazzano platform operator with the private registry and repository used to load the images.

To obtain the required Verrazzano images and install from your private registry, you must:

1. Download the Verrazzano ZIP file from the Oracle Software Delivery Cloud.
   * In your browser, go to the [Oracle Software Delivery Cloud](https://edelivery.oracle.com) and log in with your credentials.
   * In the drop-down menu preceding the search bar, select **Download Package**.
   * In the search bar, enter `Verrazzano Enterprise Container Platform` and click **Search**.
   * Select the `DLP: Oracle Verrazzano Enterprise Edition {{<download_package_version>}}` link.  This will add it to your download queue.
   * At the top of the page, select the **Continue** link.
   * Review the Download Queue, then click **Continue**.
   * Accept the license agreement and click **Continue**.
   * Download the file:
     * To download the ZIP file directly, select the file link in the list.
     * To download the ZIP file using `Oracle Download Manager`, click **Download** and run the `Oracle Download Manager` executable.
2. Prepare to do the private registry installation.
   * Extract the ZIP archive to a desired directory location.  There will be two files: a compressed TAR file containing the product
     files and a checksum file.
   * (Optional) In the expanded archive directory, validate that the checksum and TAR file match.  For example,
     ```
     $ shasum -c  verrazzano_{{<download_package_full_version>}}.tar.gz.sha256

     # Sample output
     verrazzano_{{<download_package_full_version>}}.tar.gz: OK
     ```
   * Expand the TAR file, for example, `tar xvf verrazzano_{{<download_package_full_version>}}.tar.gz`.
3. Load the product images into your private registry and install Verrazzano using the instructions in the `README.md`
   file that is packaged with the TAR file.

## Configuring access to an insecure private registry

A private Docker registry is called an [insecure registry](https://docs.docker.com/registry/insecure/) when it is configured for access using a self-signed certificate or over an unencrypted HTTP connection. Depending on the platform, there could be some additional configuration required for installing Verrazzano with an insecure registry.

For example, for the [Oracle Cloud Native Environment platform]({{< relref "/docs/setup/platforms/OLCNE/OLCNE.md" >}}), insecure registries must be configured in `/etc/containers/registries.conf` as follows on the worker nodes:
 ```
 [registries]
    [registries.insecure]
      registries = ["insecure-registry-1:1001/registry1","insecure-registry-2:1001/registry2"]
 ```
