---
title: Install Verrazzano in a Disconnected Environment
description:
weight: 5
description: Set up Verrazzano in environments without direct connection to the Internet
draft: false
---

If you are running in a disconnected environment (without access to the Internet), then you will need to install Verrazzano using a private container registry.
However, you may choose to install Verrazzano using a private registry even if you are not running in a disconnected environment.

You must have the following software installed:

 - [Docker](https://docs.docker.com/get-docker/)
 - [kubectl](https://kubernetes.io/docs/tasks/tools/)
 - [Helm](https://helm.sh/docs/intro/install/) (version 3.x+)
 - [jq](https://github.com/stedolan/jq/wiki/Installation)

 Installing Verrazzano using a private Docker-compliant container registry requires the following:

 * Loading all required Verrazzano container images into your own registry and repository.
 * Installing the Verrazzano platform operator with the private registry and repository used to load the images.

## Get Verrazzano

You can download Verrazzano from the Verrazzano GitHub releases page. Oracle customers also can get Verrazzano from the
Oracle Software Delivery Cloud. Follow the respective download instructions:

- [From GitHub](#from-github)
- [From the Oracle Software Delivery Cloud](#from-the-oracle-software-delivery-cloud)


 ### From GitHub

 1. Download the desired Verrazzano distribution from the GitHub releases page.

    a. In your browser, go to [Verrazzano releases](https://github.com/verrazzano/verrazzano/releases).

    b. Download the distribution TAR file, `verrazzano-<major>.<minor>.<patch>-<operating system>-<architecture>.tar.gz`, and the corresponding checksum file.

    c. In the downloaded directory, validate that the checksum and TAR files match.
     For example, if you have downloaded `verrazzano-{{<verrazzano_development_version>}}-linux-amd64.tar.gz`:
{{< clipboard >}}
<div class="highlight">

  ```
  $ sha256sum -c verrazzano-{{<verrazzano_development_version>}}-linux-amd64.tar.gz.sha256
  # Sample output
  verrazzano-{{<verrazzano_development_version>}}-linux-amd64.tar.gz: OK
  ```
</div>
{{< /clipboard >}}
   **NOTE**: Use the `sha256sum` command on Linux and `shasum` on MacOS.

    d. Expand the TAR file to access the release artifacts.

    The following example, extracts the distribution archive `verrazzano-{{<verrazzano_development_version>}}-linux-amd64.tar.gz` into the current directory.
{{< clipboard >}}
<div class="highlight">

  ```
  $ tar xvf verrazzano-{{<verrazzano_development_version>}}-linux-amd64.tar.gz
  ```
</div>
{{< /clipboard >}}
   After a successful extraction, the release artifacts will be under the `verrazzano-{{<verrazzano_development_version>}}` directory.

    e. Define an environment variable `DISTRIBUTION_DIR`.
{{< clipboard >}}
<div class="highlight">

  ```
   $ DISTRIBUTION_DIR=<path to the current directory>/verrazzano-{{<verrazzano_development_version>}}
  ```
</div>
{{< /clipboard >}}

2. Download the Verrazzano images defined in the BOM, `${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json`, using the script, `${DISTRIBUTION_DIR}/bin/vz-registry-image-helper.sh`.
{{< clipboard >}}
<div class="highlight">

  ```
  $ sh ${DISTRIBUTION_DIR}/bin/vz-registry-image-helper.sh \
     -b ${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json \
     -f ${DISTRIBUTION_DIR}/images  
  ```  
</div>
{{< /clipboard >}}

   The previous command downloads all the images to the `${DISTRIBUTION_DIR}/images` directory. 	 	  		 

### From the Oracle Software Delivery Cloud

1. Download the Verrazzano ZIP file.
    * Download the Verrazzano ZIP file from the Oracle Software Delivery Cloud for major or minor releases.

        a. In your browser, go to the [Oracle Software Delivery Cloud](https://edelivery.oracle.com) and log in with your credentials.

        b. In the drop-down menu preceding the search bar, select **All Categories**.

        c. In the search bar, enter `Verrazzano Enterprise Container Platform` and click **Search**.

        d. Select the `REL: Verrazzano Enterprise Container Platform {{<download_package_full_version>}}` link. This will add it to your download queue.

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

2. Prepare to do the private registry installation.

    a. Extract the ZIP archive to a desired directory location. There will be two files: a compressed TAR file containing the product files and a checksum file.

    b. Define an environment variable `DISTRIBUTION_DIR`.
     ```
     $ DISTRIBUTION_DIR=<path to the current directory>/verrazzano-{{<verrazzano_development_version>}}
     ```
    c. In the expanded archive directory, validate that the checksum and TAR files match. For example,
      ```
      $ sha256sum -c verrazzano-{{<verrazzano_development_version>}}.tar.gz.sha256
      # Sample output
      verrazzano-{{<verrazzano_development_version>}}.tar.gz: OK
      ```
      **NOTE**: Use the `sha256sum` command on Linux and `shasum` on MacOS.    

## Load the images

Load the product images into your private registry.

1. To log in to the Docker registry, run `docker login <SERVER>` with your credentials.

2. For use with the examples in this document, define the following variables with respect to your target registry and repository: `MYREG`, `MYREPO`, `VPO_IMAGE`.    

    These identify the target Docker registry and repository, and the Verrazzano platform operator image, as defined in the BOM file. For example, using a target registry of `myreg.io` and a target repository of `myrepo/v8o`:
{{< clipboard >}}
<div class="highlight">

  ```
   $ MYREG=myreg.io
   $ MYREPO=myrepo/v8o
   $ VPO_IMAGE=$(cat ${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json \
      | jq -r '.components[].subcomponents[] | select(.name == "verrazzano-platform-operator") \
      | "\(.repository)/\(.images[].image):\(.images[].tag)"')
   ```
</div>
{{< /clipboard >}}

3. Run the `${DISTRIBUTION_DIR}/bin/vz-registry-image-helper.sh` script to push the images to the registry:
{{< clipboard >}}
<div class="highlight">

   ```
   $ sh ${DISTRIBUTION_DIR}/bin/vz-registry-image-helper.sh \
    -t $MYREG -r $MYREPO -l ${DISTRIBUTION_DIR}/images
   ```   
</div>
{{< /clipboard >}}
4. Although most images can be protected using credentials stored in an image pull secret, some images _must_ be public. Use the following commands to get the list of public images:

   * The Rancher Agent image.
{{< clipboard >}}
<div class="highlight">

   ```
   $ cat ${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json \
    | jq -r '.components[].subcomponents[] | select(.name == "rancher") \
    | .images[] | select(.image == "rancher-agent") | "\(.image):\(.tag)"'
   ```
</div>
{{< /clipboard >}}

   * All the Rancher images in the `rancher/additional-rancher` subcomponent.
{{< clipboard >}}
<div class="highlight">

   ```
   $ cat ${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json \
    | jq -r '.components[].subcomponents[] | select(.name == "additional-rancher") \
    | .images[] | "\(.image):\(.tag)"'
   ```
</div>
{{< /clipboard >}}

   * The Verrazzano platform operator image identified by `$VPO_IMAGE`, as defined previously in Step 2.

   * For all the Verrazzano Docker images in the private registry that are not explicitly marked public, you will need to create the secret `verrazzano-container-registry` in the `default` namespace, with the appropriate credentials for the registry, identified by `$MYREG`.    
  For example:
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl create secret docker-registry verrazzano-container-registry \  
        --docker-server=$MYREG --docker-username=myreguser \  
        --docker-password=xxxxxxxx --docker-email=me@example.com
   ```     
</div>
{{< /clipboard >}}

## Install Verrazzano

1. Install the Verrazzano platform operator using the image defined by `$MYREG/$MYREPO/$VPO_IMAGE`.  
{{< clipboard >}}
<div class="highlight">

  ```
  $ helm template --include-crds ${DISTRIBUTION_DIR}/manifests/charts/verrazzano-platform-operator \
      --set image=${MYREG}/${MYREPO}/${VPO_IMAGE} --set global.registry=${MYREG} \
      --set global.repository=${MYREPO} --set global.imagePullSecrets={verrazzano-container-registry} | kubectl apply -f -
   ```
</div>
{{< /clipboard >}}

1. Wait for the deployment of the Verrazzano platform operator.
{{< clipboard >}}
<div class="highlight">

  ```
  $ kubectl -n verrazzano-install rollout status deployment/verrazzano-platform-operator

  # Sample output
    deployment "verrazzano-platform-operator" successfully rolled out
  ```      
</div>
{{< /clipboard >}}

1. Confirm that the Verrazzano platform operator pod is running.
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl -n verrazzano-install get pods

   # Sample output
     NAME                                            READY   STATUS    RESTARTS   AGE
     verrazzano-platform-operator-74f4547555-s76r2   1/1     Running   0          114s
   ```   
</div>
{{< /clipboard >}}

The distribution archive includes the supported installation profiles under `${DISTRIBUTION_DIR}/manifests/profiles`.
     Verrazzano supports customizing installation configurations. See [Modify Verrazzano Installations]({{< relref "/docs/setup/modify-installation.md" >}}).      

To create a Verrazzano installation using the provided profiles, run the following command:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f $DISTRIBUTION_DIR/manifests/profiles/prod.yaml
```  
</div>
{{< /clipboard >}}
For a complete description of Verrazzano configuration options, see the [Reference API]({{< relref "/docs/reference/_index.md" >}}).     
