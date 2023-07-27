---
title: Persistent Storage
description: Customize persistent storage settings
linkTitle: Persistent Storage
Weight: 11
draft: false
---

The following components can use persistent storage:

  - OpenSearch
  - OpenSearch Dashboards
  - Prometheus
  - Grafana
  - Keycloak/MySQL

By default, each Verrazzano installation profile has different storage characteristics.  The `dev` profile uses ephemeral
storage only, but in all other profiles, each of the listed components use persistent storage.  For more information, see [Profile Configurations]({{< relref "/docs/setup/install/profiles.md#profile-configurations" >}}).

{{< alert title="NOTE" color="warning" >}}
Ephemeral storage is not recommended for use in production; Kubernetes pods can be restarted at any time, leading to
a loss of data and system instability if non-persistent storage is used.  Persistent storage is recommended
for all use cases beyond evaluation or development.
{{< /alert >}}

While each profile has its own default persistence settings, in each case you have the option to override the profile
defaults to customize your persistence settings.

You can customize the persistence settings for these components through the
[VerrazzanoSpec](/docs/reference/api/verrazzano/v1beta1/#verrazzanospec), as follows:

* Overriding the persistence settings for all components (Keycloak, Grafana, Prometheus, OpenSearch, and OpenSearch Dashboards) by using the `defaultVolumeSource` field.
* Overriding the persistence settings for Keycloak by using the `volumeSource` field on that component's configuration.

You can set the global `defaultVolumeSource` and component-level `volumeSource` fields to one of the following values:

| Value | Storage
| ------------- |:-------------
| [`emptyDir`](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) | Ephemeral storage; should not be used for production scenarios.
| [`persistentVolumeClaim`](https://kubernetes.io/docs/reference/generated/kubernetes-api/{{<kubernetes_api_version>}}/#persistentvolumeclaimvolumesource-v1-core) | A `PersistentVolumeClaimVolumeSource` where the `claimSource` field references a named `volumeClaimSpecTemplate`.

When you want to use a `persistentVolumeClaim` to override the storage settings for components, you must do the following:

* Create a [volumeClaimSpecTemplate](/docs/reference/api/verrazzano/v1beta1/#volumeclaimspectemplate) which identifies
  the desired persistence settings.
* Configure a `persistentVolumeClaim` for the component where the `claimName` field references the template you created previously.

This lets you create named persistence settings that can be shared across multiple components within a Verrazzano
configuration.  Note that the existence of a persistence template in the `volumeClaimSpecTemplates` list does not
directly result in the creation of a persistent volume, or affect any component storage settings until it is referenced
by either `defaultVolumeSource` or a specific component's `volumeSource`.

## Examples
Review the following customizing persistent storage examples:

- [Customize persistence globally using `defaultVolumeSource`](#customize-persistence-globally-using-defaultvolumesource)
- [Customize PersistentVolumeClaim settings for Keycloak using `volumeSource`](#customize-persistentvolumeclaim-settings-for-keycloak-using-volumesource)
- [Use global and local persistence settings together](#use-global-and-local-persistence-settings-together)

### Customize persistence globally using `defaultVolumeSource`

If `defaultVolumeSource` is configured, then that setting will be used for all components that require storage.

For example, the following Verrazzano configuration uses the `prod` profile, but disables persistent storage for all components.

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: no-storage-prod
spec:
  profile: prod
  defaultVolumeSource:
      emptyDir: {}
```

The following example uses `persistentVolumeClaim` to override persistence settings globally for a `prod` profile, to use
`100Gi` volumes for all components, instead of the default of `50Gi`.

```
apiVersion: install.verrazzano.io/v1beta1
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

The following example uses a `managed-cluster` profile but overrides the persistence settings to use ephemeral storage.

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: mgdcluster-empty-storage-example
spec:
  profile: managed-cluster
  defaultVolumeSource:
    emptyDir: {}  # Use emphemeral storage for all Components unless overridden
```

### Customize PersistentVolumeClaim settings for Keycloak using `volumeSource`

The following example Verrazzano configuration enables a `100Gi` PersistentVolumeClaim for the MySQL component in Keycloak
in a `dev` profile configuration.  This overrides the default of ephemeral storage for Keycloak in that profile, while
retaining the default storage settings for other components.

```
apiVersion: install.verrazzano.io/v1beta1
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

### Use global and local persistence settings together

The following example uses a `dev` installation profile, but overrides the profile persistence settings to:

* Use `200Gi` volumes for all components by default.
* Use a `100Gi` volume for the MySQL instance associated with Keycloak.

```
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: dev-storage-example
spec:
  profile: dev
  defaultVolumeSource:
    persistentVolumeClaim:
      claimName: vmi     # Set storage globally for the metrics stack
  components:
    keycloak:
      mysql:
        volumeSource:
          persistentVolumeClaim:
            claimName: mysql  # Set storage separately for keycloak's MySql instance
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
