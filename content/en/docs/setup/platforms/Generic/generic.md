---
title: Generic Kubernetes
description: Instructions for setting up a generic Kubernetes cluster for Verrazzano
linkTitle: Generic
Weight: 10 
draft: false
---

### Prepare for the generic install

To use a generic Kubernetes implementation, there are two main areas you can configure: ingress and storage.

{{< tabs tabTotal="3" tabID="3" tabName1="Ingress" tabName2="Storage" >}}
{{< tab tabNum="1" >}}
<br>

You can achieve ingress configuration using Helm overrides.  For example, to use the `nginx-controller` for ingress on KIND, apply the following customization to the Verrazzano CRD.

```shell
spec: 
 components:
  ingress:
   nginxInstallArgs:
   - name: controller.kind
     value: DaemonSet
   - name: controller.hostPort.enabled
     value: "true"
   - name: controller.nodeSelector.ingress-ready
     value: "true"
     setString: true
   - name: controller.tolerations[0].key
     value: node-role.kubernetes.io/master
   - name: controller.tolerations[0].operator
     value: Equal
   - name: controller.tolerations[0].effect
     value: NoSchedule
```

{{< /tab >}}
{{< tab tabNum="2" >}}
<br>

Each Verrazzano install profile has different storage characteristics by default.  Some components have external storage requirements (expressed through `PersistentVolumeClaim` declarations in their resources/helm charts):

  - MySQL
  - ElasticSearch
  - Prometheus
  - Grafana

By default, the prod  profile uses 50Gi persistent volumes for each of the above services, using the default storage class for the target Kubernetes platform.  The dev  profile uses ephemeral EmptyDir storage by default.  However, you can customize these storage settings within a profile as desired.

To override these settings, the Verrazzano install resource can be customized by defining a [VolumeSource](https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/volume/) on the `DefaultVolumeSource` field in the install CR, which can be one of

  - [emptyDir](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) 
  - [persistentVolumeClaim](https://v1-18.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#persistentvolumeclaimvolumesource-v1-core) 

Configuring emptyDir for the DefaultVolumeSource forces all persistent volumes created by Verrazzano components in an installation to use ephemeral storage unless otherwise overridden.  This can be useful for development or test scenarios. 

A [persistentVolumeClaim](https://v1-18.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#persistentvolumeclaimvolumesource-v1-core) can be used to identify a that references a `volumeClaimSpecTemplate` in the `volumeClaimSpecTemplates` section via the `claimSource` field.  A `volumeClaimSpecTemplate` is a named [PersistentVolumeClaimSpec](https://v1-18.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#persistentvolumeclaimspec-v1-core) configuration.  A `volumeClaimSpecTemplate` can be referenced from more than one component; it merely identifies  configuration settings, and does not result in a direct instantiation of a persistent volume.  The settings are utilized by referencing components when creating their [PersistentVolumeClaims](https://v1-18.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#persistentvolumeclaim-v1-core) at install time.

You can override the `DefaultVolumeSource` setting at the component level by defining a supported `VolumeSource` on that component, if the component supports it.  At present only the `keycloak/mysql` component supports a volumeSource field override.

#### Examples

The following example shows how to define a dev  profile with different persistence settings for the monitoring components and the Keycloak/MySQL instance.

```shell
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: kind-verrazzano-with-persistence
spec:
  environmentName: default
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
  - name: default      # "default" is a known template name, and will be used by Verrazzano components by default if no other template is referenced explicitly
    spec:
      resources:
        requests:
          storage: 2Gi 
  - name: mysql      # separate template to allow MySQL to define it's own settings
    spec:
      resources:
        requests:
          storage: 5Gi  # default

```

The following example shows how to define a dev profile where all resources use emptyDir by default.


```shell
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: storage-example-dev
spec:
  profile: dev
  defaultVolumeSource:
    emptyDir: {}  # Use emphemeral storage for dev mode for all Components
```

{{< /tab >}}
{{< /tabs >}}

