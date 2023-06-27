---
title: Customize clusterAPI
linkTitle: Customize clusterAPI
description: Customize clusterAPI settings
weight: 6
draft: false
---

The clusterAPI component allows you to quickly create managed clusters and manage them in the Verrazzano console. See [Cluster API]({{< relref "/docs/setup/provision-cluster/CAPI" >}}) for more information.

You can customize the clusterAPI component using component overrides in the Verrazzano custom resource. Refer to the [clusterAPI reference]({{< relref "/docs/reference/vpo-verrazzano-v1beta1#install.verrazzano.io/v1beta1.ClusterAPIComponent" >}}) to see which overrides are available.

## Upgrade providers

You can upgrade the individual providers that make up the clusterAPI component. This allows you to take advantage of new features in the providers without upgrading your entire Verrazzano installation.

This example customizes the clusterAPI component as follows:

* Sets the `version` of both the OCNE bootstrap provider and the OCNE control plane provider to `1.0`

    **NOTE**: Since the OCNE bootstrap and OCNE control plane providers are bundled together, make sure to set their overrides to the same version or it may lead to unexpected behavior.

* Sets the `version` of the OCI infrastructure provider to `0.10.0`


{{< clipboard >}}
<div class="highlight">

 ```
 apiVersion: install.verrazzano.io/v1beta1
 kind: Verrazzano
 metadata:
   name: example-verrazzano
 spec:
   profile: dev
   components:
    clusterAPI:
        enabled: true
        overrides:
        - values:
            defaultProviders:
                ocneBootstrap:
                    version: 1.0
                ocneControlPlane:
                    version: 1.0
                oci:
                    version: v0.10.0
 ```
</div>
{{< /clipboard >}}


## Use a private registry

If you want to upgrade the clusterAPI providers but your Verrazzano instance is installed in disconnected environment, you can configure the clusterAPI component to retrieve the provider assets from another location, instead of the public repository.

1. Place the provider assets in a location that is accessible by your disconnected Verrazzano environment.
1. In the Verrazzano custom resource, add a `global.registry` override and then enter a name for your private registry as its value. 
1. For each provider that you want to upgrade, add a `url` override and then enter the path to the provider assets in the private registry for your environment. 

For example:
{{< clipboard >}}
<div class="highlight">

 ```
 apiVersion: install.verrazzano.io/v1beta1
 kind: Verrazzano
 metadata:
   name: example-verrazzano
 spec:
   profile: dev
   components:
    clusterAPI:
        enabled: true
        overrides:
        - values:
            global:
                registry: my.registry
            defaultProviders:
                ocneBootstrap:
                    url: https://my.private.network/cluster-api-provider-ocne/releases/tag/v1.0.0
                ocneControlPlane:
                    url: https://my.private.network/cluster-api-provider-ocne/releases/tag/v1.0.0
                oci:
                    url: https://my.private.network/cluster-api-provider-oci/releases/tag/v0.10.0
 ```

</div>
{{< /clipboard >}}