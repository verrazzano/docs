---
title: Use a Private Registry
description: Instructions for setting up Verrazzano using a private container registry
Weight: 8
draft: false
---

Verrazzano Distribution includes a collection of Kubernetes manifests to deploy the Verrazzano platform operator and distribution artifacts, built for Linux and Darwin operating systems.
The distribution artifacts are available for ADM64 and ARM64 architectures.

The distributions includes:
* [Verrazzano CLI]({{< relref "docs/setup/cli/_index.md" >}}).
* [Installation Profiles]({{< relref "/docs/setup/install/profiles.md"  >}}).
* Helper scripts to download the images from the bill of materials (BOM) and to upload the Verrazzano images to a private registry.
* Helm charts for the Verrazzano Platform Operator.
* `README.md` providing the layout of the respective distribution.

You can install Verrazzano using a private Docker-compliant container registry. This requires the following:

* Loading all required Verrazzano container images into your own registry and repository.
* Installing the Verrazzano platform operator with the private registry and repository used to load the images.

## Prerequisites
You must have the following software installed:

 - [Docker](https://docs.docker.com/get-docker/)
 - [kubectl](https://kubernetes.io/docs/tasks/tools/)
 - [Helm](https://helm.sh/docs/intro/install/) (version 3.x+)
 - [jq](https://github.com/stedolan/jq/wiki/Installation)

## Load the images

1. Download the required Verrazzano distribution from Github.
   * In your browser, go to the [Verrazzano releases](https://github.com/verrazzano/verrazzano/releases) 
   * Download the distribution TAR file - `verrazzano-<major>.<minor>.<patch>-<operating system>-<architecture>.tar.gz` and the corresponding checksum file.
   * In the downloaded directory, validate that the checksum and the TAR file match. For example,
     ```
     $ sha256sum -c  verrazzano-<major>.<minor>.<patch>-<operating system>-<architecture>.tar.gz.sha256

     # Sample output
     verrazzano-<major>.<minor>.<patch>-<operating system>-<architecture>.tar.gz: OK
     ```
     Use sha256sum command on Linux and shasum on MacOS.
   * Expand the TAR file to get the release artifacts.     
     The following example, extracts the distribution archive in the current directory.
     ```
     $ tar xvf verrazzano-<major>.<minor>.<patch>-<operating system>-<architecture>.tar.gz
     ```
     After a successful extraction, you will find the release artifacts under directory `verrazzano-<major>.<minor>.<patch>`.        
     For use in this section, define an environment variable `DISTRIBUTION_DIR`.
     ```
     DISTRIBUTION_DIR=<local directory>/verrazzano-<major>.<minor>.<patch>
     ```
          
2. Download the Verrazzano images 
   * Download the Verrazzano images defined in Bill of Materials (BOM file) - `${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json`, using the script `${DISTRIBUTION_DIR}/bin/vz-registry-image-helper.sh`.
     ```
     sh ${DISTRIBUTION_DIR}/bin/vz-registry-image-helper.sh -b ${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json -f ${DISTRIBUTION_DIR}/images    
     ```  
     The above command downloads the images to all the images `${DISTRIBUTION_DIR}/images` directory.      

3. Load the product images into your private registry
   * Log in to the Docker registry, run `docker login [SERVER]` with your credentials.
   * For use with the examples in this document, define the following variables with respect to your target registry and repository:
       * `MYREG`
       * `MYREPO`
       * `VPO_IMAGE`    

     These identify the target Docker registry and repository, and the Verrazzano Platform Operator image, as defined in the BOM file. For example, using a target registry of `myreg.io` and a target repository of `myrepo/v8o`:

     ```
     MYREG=myreg.io
     MYREPO=myrepo/v8o
     VPO_IMAGE=$(cat ${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json | jq -r '.components[].subcomponents[] | select(.name == "verrazzano-platform-operator") | "\(.repository)/\(.images[].image):\(.images[].tag)"')
     ```
   * Run `${DISTRIBUTION_DIR}/bin/vz-registry-image-helper.sh` script to push images to the registry:    
     ```
     $ sh ${DISTRIBUTION_DIR}/bin/vz-registry-image-helper.sh -t $MYREG -r $MYREPO -l ${DISTRIBUTION_DIR}/images
     ```

     Although most images can be protected using credentials stored in an image pull secret, some images must **must** be public. Use the following commands to get the list of public images:

     * All the Rancher images in the `rancher/additional-rancher` subcomponent.
       ```
       $ cat ${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json | jq -r '.components[].subcomponents[] | select(.name == "additional-rancher") | .images[] | "\(.image):\(.tag)"'
       ```
     * The Fluentd kubernetes daemonset image.
       ```
       $ cat ${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json | jq -r '.components[].subcomponents[].images[] | select(.image == "fluentd-kubernetes-daemonset") | "\(.image):\(.tag)"'
       ```
     * The Istio proxy image.
       ```
       $ cat ${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json | jq -r '.components[].subcomponents[] |  select(.name == "istiod") | .images[] | select(.image == "proxyv2") | "\(.image):\(.tag)"'
       ```
     * The WebLogic Monitoring Exporter image.
       ```
       $ cat ${DISTRIBUTION_DIR}/manifests/verrazzano-bom.json | jq -r '.components[].subcomponents[].images[] | select(.image == "weblogic-monitoring-exporter") | "\(.image):\(.tag)"'
       ```
     * The Verrazzano Platform Operator image identified by `$VPO_IMAGE`, as defined above.    
   
     For all the Verrazzano Docker images in the private registry that are not explicitly marked public, you will need to create the secret `verrazzano-container-registry` in the `default` namespace, with the appropriate credentials for the registry, identified by `$MYREG`.    
     For example,
     ```
     $ kubectl create secret docker-registry verrazzano-container-registry \  
	      --docker-server=$MYREG --docker-username=myreguser \  
	      --docker-password=xxxxxxxx --docker-email=me@example.com
     ```     
     
## Install Verrazzano    
   * Install the Verrazzano Platform Operator using the image defined by `$MYREG/$MYREPO/$VPO_IMAGE`.  

     ```
     helm template --include-crds ${DISTRIBUTION_DIR}/manifests/charts/verrazzano-platform-operator \
         --set image=${MYREG}/${MYREPO}/${VPO_IMAGE} --set global.registry=${MYREG} \
         --set global.repository=${MYREPO} --set global.imagePullSecrets={verrazzano-container-registry} | kubectl apply -f -
     ```
     
     Wait for the deployment of Verrazzano Platform Operator.
     ```
     $ kubectl -n verrazzano-install rollout status deployment/verrazzano-platform-operator
     
     # Sample output
       deployment "verrazzano-platform-operator" successfully rolled out
     ```      
     
     Confirm that the Verrazzano Platform Operator pod is running.
     ```
     $ kubectl -n verrazzano-install get pods
     
     # Sample output
       NAME                                            READY   STATUS    RESTARTS   AGE
       verrazzano-platform-operator-74f4547555-s76r2   1/1     Running   0          114s
     ```    
   * The distribution archive includes the supported installation profiles under `${DISTRIBUTION_DIR}/manifests/profiles`.
     Verrazzano supports customizing installation configurations. See [Customize Installations](https://verrazzano.io/{{<release_version>}}/docs/setup/customizing/).      

     To create a Verrazzano installation using the provided profiles, run the following command:
     ```
     $ kubectl apply -f $DISTRIBUTION_DIR/manifests/profiles/prod.yaml
     ```     
     For a complete description of Verrazzano configuration options, refer [Reference API](https://verrazzano.io/{{<release_version>}}/docs/reference/api/).     


## Configuring access to an insecure private registry

A private Docker registry is called an [insecure registry](https://docs.docker.com/registry/insecure/) when it is configured for access using a self-signed certificate or over an unencrypted HTTP connection. Depending on the platform, there could be some additional configuration required for installing Verrazzano with an insecure registry.

For example, for the [Oracle Cloud Native Environment platform]({{< relref "/docs/setup/platforms/OLCNE/OLCNE.md" >}}), insecure registries must be configured in `/etc/containers/registries.conf` as follows on the worker nodes:
 ```
 [registries]
    [registries.insecure]
      registries = ["insecure-registry-1:1001/registry1","insecure-registry-2:1001/registry2"]
 ```
