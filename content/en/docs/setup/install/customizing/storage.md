---
title: Customizing Persistence Settings
description: Customizing persistent storage settings for Verrazzano
linkTitle: Customizing Persistence
Weight: 10
draft: false
---

The following components allow for persistent storage usage:

  - Elasticsearch
  - Prometheus
  - Grafana
  - Keycloak/MySQL

As mentioned in the [Profiles]({{< relref "/docs/setup/install/profiles.md" >}}) document, each Verrazzano install profile 
has different storage characteristics by default.  The `dev` profile uses only ephemeral storage, but in all other profiles, 
each of the above components use persistent storage.

For install profiles other than `dev`, the default storage requests are as follows:

| Component | Storage 
| ------------- |:-------------:  
| Elasticsearch | 50Gi<br/>(Data nodes) 
| Prometheus | 50Gi 
| Grafana | 50Gi 
| Keycloak | 50Gi 

## Customizing Persistent Storage

The persistence settings for Verrazzano components can be customized through the following means in the
[VerrazzanoSpec](/docs/reference/api/verrazzano/verrazzano/#verrazzanospec):

* Globally overriding the persistence settings for all components through the `defaultVolumeSource` field
* Overriding the persistence settings for an individual component through a `volumeSource` field on that component's configuration

At present, only the `MySQL` component under `Keycloak` can be individually configured.

The global `defaultVolumeSource` and component-level `volumeSource` fields can be set to one of the following values:

| Component | Storage
| ------------- |:-------------
| [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) | Ephemeral storage; this can be useful for development or test scenarios
| [`persistentVolumeClaim`](https://v1-18.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#persistentvolumeclaimvolumesource-v1-core) | A `PersistentVolumeClaimVolumeSource` where the `claimSource` field references a named `volumeClaimSpecTemplate`.

In the case where you want to use a `persistentVolumeClaim` to override the storage settings for components, you must do the following:

* Create a [volumeClaimSpecTemplate](/docs/reference/api/verrazzano/verrazzano/#volumeclaimspectemplate) which identifies
  your desired persistence settings 
* Configure a `persistentVolumeClaim` for the component where the `claimName` field references the template you created above

This allows you to create named persistence settings "templates" that can be shared across multiple components within a Verrazzano
configuration.  Note that the existence of a persistence template in the `volumeClaimSpecTemplates` list does not 
directly result in the creation of a persistent volume, or affect any component storage settings until it is referenced 
by either `defaultVolumeSource` or a specific component's `volumeSource`.

## Examples

### Customizing Persistence Globally via `defaultVolumeSource`

If the `defaultVolumeSource` field is configured, then that setting will be used for all components that required storage.

For example, the following Verrazzano configuration uses the `prod` profile, but disables persistent storage for all components,
forcing them to use emphemeral storage:

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

The next example uses a `persistentVolumeClaim` to globally override persistence settings for a `prod` profile to use 
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

### Customizing PersistentVolumeClaim Settings For a Component Using `volumeSource`

The following example Verrazzano configuration enables a `100Gi` PersistentVolumeClaim for the MySQL component in Keycloak 
in a `dev` profile configuration, overriding the default that uses ephemeral storage for that profile, while using ephemeral
storage for everything else:

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
