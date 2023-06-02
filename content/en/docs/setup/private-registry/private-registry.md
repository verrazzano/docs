---
title: Use a Private Registry
description: Set up Verrazzano using a private container registry
Weight: 4
draft: false
---

**NOTE**: If you are running in a disconnected environment (without access to the Internet), then you will need to install Verrazzano using a private container registry.

Installing Verrazzano using a private Docker-compliant container registry requires the following:

* Loading all required Verrazzano container images into your own registry and repository.
* Installing the Verrazzano platform operator with the private registry and repository used to load the images.

You must have the following software installed:

 - [Docker](https://docs.docker.com/get-docker/)
 - [kubectl](https://kubernetes.io/docs/tasks/tools/)
 - [Helm](https://helm.sh/docs/intro/install/) (version 3.x+)
 - [jq](https://github.com/stedolan/jq/wiki/Installation)

 The Verrazzano distribution contains Kubernetes manifests to deploy Verrazzano, client binaries, and various other utilities. These distributions are provided for Linux and MacOS operating systems on AMD and ARM architectures.

 This distribution includes:
 * [Verrazzano CLI]({{< relref "docs/setup/install/prepare/cli-setup.md" >}})
 * [Installation Profiles]({{< relref "/docs/setup/install/perform/profiles.md" >}})
 * Helper scripts to download the images from the bill of materials (BOM) and to upload the Verrazzano images to a private registry
 * Helm charts for the Verrazzano platform operator
 * `README.md` which provides the layout of the distribution

## Load the images

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

1. Download the Verrazzano images defined in the BOM, `${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json`, using the script, `${DISTRIBUTION_DIR}/bin/vz-registry-image-helper.sh`.
{{< clipboard >}}
<div class="highlight">

   ```
   $ sh ${DISTRIBUTION_DIR}/bin/vz-registry-image-helper.sh -b ${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json -f ${DISTRIBUTION_DIR}/images  
   ```  
</div>
{{< /clipboard >}}
    The previous command downloads all the images to the `${DISTRIBUTION_DIR}/images` directory. 	 

1. Load the product images into your private registry.

    a. To log in to the Docker registry, run `docker login <SERVER>` with your credentials.

    b. For use with the examples in this document, define the following variables with respect to your target registry and repository: `MYREG`, `MYREPO`, `VPO_IMAGE`.    

     These identify the target Docker registry and repository, and the Verrazzano platform operator image, as defined in the BOM file. For example, using a target registry of `myreg.io` and a target repository of `myrepo/v8o`:
{{< clipboard >}}
<div class="highlight">

   ```
   $ MYREG=myreg.io
   $ MYREPO=myrepo/v8o
   $ VPO_IMAGE=$(cat ${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json | jq -r '.components[].subcomponents[] | select(.name == "verrazzano-platform-operator") | "\(.repository)/\(.images[].image):\(.images[].tag)"')
   ```
</div>
{{< /clipboard >}}

    c. Run the `${DISTRIBUTION_DIR}/bin/vz-registry-image-helper.sh` script to push the images to the registry:
{{< clipboard >}}
<div class="highlight">

   ```
    $ sh ${DISTRIBUTION_DIR}/bin/vz-registry-image-helper.sh -t $MYREG -r $MYREPO -l ${DISTRIBUTION_DIR}/images
   ```   
</div>
{{< /clipboard >}}

     d. Although most images can be protected using credentials stored in an image pull secret, some images _must_ be public. Use the following commands to get the list of public images:

   * The Rancher Agent image.
{{< clipboard >}}
<div class="highlight">

   ```
   $ cat ${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json | jq -r '.components[].subcomponents[] | select(.name == "rancher") | .images[] | select(.image == "rancher-agent") | "\(.image):\(.tag)"'
   ```
</div>
{{< /clipboard >}}

   * All the Rancher images in the `rancher/additional-rancher` subcomponent.
{{< clipboard >}}
<div class="highlight">

   ```
   $ cat ${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json | jq -r '.components[].subcomponents[] | select(.name == "additional-rancher") | .images[] | "\(.image):\(.tag)"'
   ```
</div>
{{< /clipboard >}}

   * The Verrazzano platform operator image identified by `$VPO_IMAGE`, as defined previously in Step 3.b.

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
       Verrazzano supports customizing installation configurations. See [Customize Verrazzano]({{< relref "/docs/customize/_index.md" >}}).      

  To create a Verrazzano installation using the provided profiles, run the following command:
{{< clipboard >}}
<div class="highlight">

  ```
  $ kubectl apply -f $DISTRIBUTION_DIR/manifests/profiles/prod.yaml
  ```  
</div>
{{< /clipboard >}}
  For a complete description of Verrazzano configuration options, see the [Reference API]({{< relref "/docs/reference/_index.md" >}}).

## Configuring access to an insecure private registry

A private Docker registry is called an [insecure registry](https://docs.docker.com/registry/insecure/) when it is configured for access using a self-signed certificate or over an unencrypted HTTP connection. Depending on the platform, there could be some additional configuration required for installing Verrazzano with an insecure registry.

For example, for the [Oracle Cloud Native Environment platform]({{< relref "/docs/setup/install/prepare/platforms/OLCNE/OLCNE.md" >}}), insecure registries must be configured in `/etc/containers/registries.conf` as follows on the worker nodes:
{{< clipboard >}}
<div class="highlight">

```
 [registries]
    [registries.insecure]
      registries = ["insecure-registry-1:1001/registry1","insecure-registry-2:1001/registry2"]
 ```
</div>
{{< /clipboard >}}

## WebLogic applications

WebLogic applications require that the container registry secret be specified in the `Domain` resource. Create a registry secret in the application namespace and specify the secret in
the `imagePullSecrets` field of the WebLogic [Domain](https://github.com/oracle/weblogic-kubernetes-operator/blob/main/documentation/domains/Domain.md#domain-spec) spec for the application.

For an example, see the [ToDo List]( {{< release_source_url path=examples/todo-list/todo-list-components.yaml >}} ) example application component YAML file.
