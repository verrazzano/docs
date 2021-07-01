---
title: Customizing Persistence Settings
description: Customizing persistent storage settings for Verrazzano
linkTitle: Customizing Persistence
Weight: 10
draft: false
---

By default, each Verrazzano install profile has different storage characteristics.  The following components allow for persistent 
storage usage (expressed through `PersistentVolumeClaim` declarations in their `resources/helm` charts):

  - Elasticsearch
  - Prometheus
  - Grafana
  - MySQL (Keycloak)

{{< alert title="NOTE" color="warning" >}}
Insert a table of persistence settings by profile here
{{< /alert >}}

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
