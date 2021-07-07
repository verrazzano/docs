---
title: Customizing Persistent Storage
description: Customizing persistent storage settings for Verrazzano
linkTitle: Customizing Persistent Storage
Weight: 10
draft: false
---

The following components allow for persistent storage usage:

  - Elasticsearch
  - Prometheus
  - Grafana
  - Keycloak/MySQL

Each Verrazzano install profile has different storage characteristics by default.  The `dev` profile uses only ephemeral 
storage, but in all other profiles, each of the above components use persistent storage.  See [Profile Configurations]({{< relref "/docs/setup/install/profiles.md#profile-configurations" >}})
for details.

{{< alert title="NOTE" color="warning" >}}
Use of ephemeral storage is not recommended for production use; Kubernetes pods can be restarted at any time, leading to
a loss of data and/or system instability if non-persistent storage is used.  Using persistent storage is recommended 
for any use cases beyond evaluation or development.
{{< /alert >}}

While each profile has its own default persistence settings, in each case you have the option to override the profile 
defaults to customize your persistence settings.

## Customizing Persistent Storage

The following components can utilize persistent storage:

* Elasticsearch
* Kibana
* Prometheus
* Grafana
* Keycloak

The persistence settings for these components can be customized through the 
[VerrazzanoSpec](/docs/reference/api/verrazzano/verrazzano/#verrazzanospec) as follows:

* Overriding the persistence settings for all components (Keycloak, Grafana, Prometheus, Elasticsearch, and Kibana) through the `defaultVolumeSource` field
* Overriding the persistence settings for Keycloak through the `volumeSource` field on that component's configuration

The global `defaultVolumeSource` and component-level `volumeSource` fields can be set to one of the following values:

| Value | Storage
| ------------- |:-------------
| [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) | Ephemeral storage; should not be used for production scenarios
| [`persistentVolumeClaim`](https://v1-18.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#persistentvolumeclaimvolumesource-v1-core) | A `PersistentVolumeClaimVolumeSource` where the `claimSource` field references a named `volumeClaimSpecTemplate`.

In the case where you want to use a `persistentVolumeClaim` to override the storage settings for components, you must do the following:

* Create a [volumeClaimSpecTemplate](/docs/reference/api/verrazzano/verrazzano/#volumeclaimspectemplate) which identifies
  your desired persistence settings 
* Configure a `persistentVolumeClaim` for the component where the `claimName` field references the template you created above

This allows you to create named persistence settings that can be shared across multiple components within a Verrazzano
configuration.  Note that the existence of a persistence template in the `volumeClaimSpecTemplates` list does not 
directly result in the creation of a persistent volume, or affect any component storage settings until it is referenced 
by either `defaultVolumeSource` or a specific component's `volumeSource`.

## Examples

### Customizing Persistence Globally via `defaultVolumeSource`

If the `defaultVolumeSource` field is configured, then that setting will be used for all components that require storage.

For example, the following Verrazzano configuration uses the `prod` profile, but disables persistent storage for all components:

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: no-storage-prod
spec:
  profile: prod
  defaultVolumeSource:
      emptyDir: {}
```

The following example uses a `persistentVolumeClaim` to globally override persistence settings for a `prod` profile to use 
`100Gi` volumes for all components, instead of the default of `50Gi`:

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: prod-global-override
spec:
  profile: prod
  defaultVolumeSource:
    persistentVolumeClaim:
      claimName: globalOverride
  volumeClaimSpecTemplates:
    - metadata:
        name: globalOverride
      spec:
        resources:
          requests:
            storage: 100Gi
```

The following example uses a `managed-cluster` profile but overrides the persistence settings to use ephemeral storage:

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: mgdcluster-empty-storage-example
spec:
  profile: managed-cluster
  defaultVolumeSource:
    emptyDir: {}  # Use emphemeral storage for all Components unless overridden
```

### Customizing PersistentVolumeClaim Settings For Keycloak Using `volumeSource`

The following example Verrazzano configuration enables a `100Gi` PersistentVolumeClaim for the MySQL component in Keycloak 
in a `dev` profile configuration.  This overrides the default of ephemeral storage for Keycloak in that profile, while 
retaining the default storage settings for other components:

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: dev-mysql-storage-example
spec:
  profile: dev
  components:
    keycloak:
      mysql:
        volumeSource:
          persistentVolumeClaim:
            claimName: mysql  # Use the "mysql" PVC template for the MySQL volume configuration
  volumeClaimSpecTemplates:
  - metadata:
      name: mysql      
    spec:
      resources:
        requests:
          storage: 100Gi
```

### Using Global and Local Persistence Settings Together

The following example uses a `dev` install profile, but overrides the profile persistence settings to

* Use `200Gi` volumes for all components by default 
* Use a `100Gi` volume for the MySQL instance associated with Keycloak

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: dev-storage-example
spec:
  profile: dev
  defaultVolumeSource:
    persistentVolumeClaim:
      claimName: vmi     # set storage globally for the metrics stack
  components:
    keycloak:
      mysql:
        volumeSource:
          persistentVolumeClaim:
            claimName: mysql  # set storage separately for keycloak's MySql instance
  volumeClaimSpecTemplates:
    - metadata:
        name: mysql
      spec:
        resources:
          requests:
            storage: 100Gi
    - metadata:
        name: vmi
      spec:
        resources:
          requests:
            storage: 200Gi
```
