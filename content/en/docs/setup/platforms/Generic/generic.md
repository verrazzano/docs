---
title: Generic Kubernetes
description: Instructions for setting up a generic Kubernetes cluster for Verrazzano
linkTitle: Generic
Weight: 10
draft: false
---

## Prepare for the generic install

If your generic Kubernetes implementation provides a load balancer implementation, then you can use a default configuration of the
Verrazzano custom resource with no customizations, and follow the [Installation Guide]({{< relref "/docs/setup/install/installation.md#install-the-verrazzano-platform-operator" >}}).

Otherwise, you can install a load balancer, such as [MetalLB](https://metallb.universe.tf/). The platform setup page for
KIND clusters has more details on setting up MetalLB [here]({{< relref "/docs/setup/platforms/kind/kind.md#install-and-configure-metallb" >}}).

### Customizations
If your Kubernetes implementation requires custom configuration, then there are two main areas you can configure: ingress and storage.

{{< tabs tabTotal="3" tabID="3" tabName1="Ingress" tabName2="Storage" >}}
{{< tab tabNum="1" >}}
<br>

You can achieve ingress configuration using Helm overrides.  For example, to override the configuration of the
`nginx-controller`,  apply the following customization to the Verrazzano CRD.

```shell
spec:
 components:
  ingress:
   nginxInstallArgs:
   # nginx Helm overrides can be specified here
   - name: <name of the nginx Helm override e.g. controller.nodeSelector.ingress-ready>
     value: <value of the nginx Helm override e.g. "true">
     setString: true
```

{{< /tab >}}
{{< tab tabNum="2" >}}
<br>

By default, each Verrazzano install profile has different storage characteristics.  Some components have external storage requirements (expressed through `PersistentVolumeClaim` declarations in their `resources/helm` charts):

  - MySQL
  - Elasticsearch
  - Prometheus
  - Grafana

By default, the `prod` profile uses 50Gi persistent volumes for each of the above services, using the default storage class for the target Kubernetes platform.  The `dev` profile uses ephemeral `emptyDir` storage by default.  However, you can customize these storage settings within a profile as desired.

To override these settings, customize the Verrazzano install resource by defining a [VolumeSource](https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/volume/) on the `defaultVolumeSource` field in the install CR, which can be one of:

  - [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir)
  - [`persistentVolumeClaim`](https://v1-18.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#persistentvolumeclaimvolumesource-v1-core)

Configuring `emptyDir` for the `defaultVolumeSource` forces all persistent volumes created by Verrazzano components in an installation to use ephemeral storage unless otherwise overridden.  This can be useful for development or test scenarios.

You can use a [persistentVolumeClaim](https://v1-18.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#persistentvolumeclaimvolumesource-v1-core) to identify a `volumeClaimSpecTemplate` in the `volumeClaimSpecTemplates` section via the `claimSource` field.  A `volumeClaimSpecTemplate` is a named [PersistentVolumeClaimSpec](https://v1-18.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#persistentvolumeclaimspec-v1-core) configuration.  A `volumeClaimSpecTemplate` can be referenced from more than one component; it merely identifies configuration settings and does not result in a direct instantiation of a persistent volume.  The settings are used by referencing components when creating their [PersistentVolumeClaims](https://v1-18.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#persistentvolumeclaim-v1-core) at install time.

If the component supports it, then you can override the `defaultVolumeSource` setting at the component level by defining a supported `VolumeSource` on that component.  At present, only the `keycloak/mysql` component supports a `volumeSource` field override.

### Examples

The following example shows how to define a `dev` profile with different persistence settings for the monitoring components and the Keycloak/MySQL instance.

```shell
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: kind-verrazzano-with-persistence
spec:
  profile: dev
  defaultVolumeSource:
    persistentVolumeClaim:
      claimName: default  # Use the "default" volume template
  components:
    keycloak:
      mysql:
        volumeSource:
          persistentVolumeClaim:
            claimName: mysql  # Use the "mysql" PVC template for the MySQL volume configuration
  volumeClaimSpecTemplates:
  - metadata:
      name: default      # "default" is a known template name, and will be used by Verrazzano components by default if no other template is referenced explicitly
    spec:
      resources:
        requests:
          storage: 2Gi
  - metadata:
    spec:
      resources:
        requests:
          storage: 5Gi  # default

```

The following example shows how to define a `dev` profile where all resources use `emptyDir` by default.


```shell
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: storage-example-dev
spec:
  profile: dev
  defaultVolumeSource:
    emptyDir: {}  # Use ephemeral storage for dev mode for all Components
```

{{< /tab >}}
{{< /tabs >}}

## Next steps

To continue, see the [Installation Guide]({{< relref "/docs/setup/install/installation.md#install-the-verrazzano-platform-operator" >}}).
