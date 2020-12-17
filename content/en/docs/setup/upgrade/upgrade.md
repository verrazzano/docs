---
title: "Upgrade Guide"
linkTitle: "Upgrade"
weight: 9
draft: false
---

Upgrading an existing Verrazzano installation involves:

* Updating the Verrazzano platform operator to the [Verrazzano release version](https://github.com/verrazzano/verrazzano/releases/) to which you want to upgrade
* Updating your `Verrazzano` resource to the the same version 

Performing an upgrade will upgrade only the Verrazzano components related to the existing installation.  Upgrading will 
not have any impact on running applications.

> **NOTE:** You may only update the version field during an upgrade; updates to other fields or component configurations are not supported at this time.

## Upgrade the Verrazzano Platform Operator

In order to upgrade an existing Verrazzano installation, you must first upgrade the Verrazzano platform [operator](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/).

To upgrade the Verrazzano platform operator, follow these steps:

1. Update the Verrazzano platform operator.
   
    To update to the latest version:

    ```shell
    kubectl apply -f https://github.com/verrazzano/verrazzano/releases/latest/download/operator.yaml
    ```
   
   To update to a specific version:

    ```shell
    kubectl apply -f https://github.com/verrazzano/verrazzano/releases/download/<version>/operator.yaml
    ```
    
    where `<version>` is the desired version.  For example:

    ```shell
    kubectl apply -f https://github.com/verrazzano/verrazzano/releases/download/v0.6.0/operator.yaml
    ```


1. Wait for the deployment to complete.

    ```shell
    $ kubectl -n verrazzano-install rollout status deployment/verrazzano-platform-operator
    deployment "verrazzano-platform-operator" successfully rolled out
    ```

1. Confirm that the operator pod is correctly defined and running.

    ```shell
    $ kubectl -n verrazzano-install get pods
    NAME                                            READY   STATUS    RESTARTS   AGE
    verrazzano-platform-operator-59d5c585fd-lwhsx   1/1     Running   0          114s
    ```

## Upgrade Verrazzano

To perform the upgrade, follow these steps:

1. Update the `Verrazzano` resource to the desired version.

      To upgrade the Verrazzano components, you must update the `version` field in your `Verrazzano` resource spec to
      match the version supported by the platform operator to which you upgraded and apply it to the cluster.
      
      The `version` field of the resource spec must a [Semantic Versioning](https://semver.org/) value
      corresponding to a valid [Verrazzano release version](https://github.com/verrazzano/verrazzano/releases/).

      You can update the resource by either:
      
      a) Editing the YAML file you used to install Verrazzano and setting the version field to the latest version, for example, `v0.7.0`.
         For example, to upgrade to `v0.7.0`, your YAML file should be edited to add or update the version field:
         
      ```yaml
      apiVersion: install.verrazzano.io/v1alpha1
      kind: Verrazzano
      metadata:
        name: my-verrazzano
      spec:
        profile: dev
        version: v0.7.0
      ```

      b) Editing the `Verrazzano` resource directly using `kubectl` and setting the version field directly, for example:
   
      ```shell
      kubectl edit verrazzano my-verrazzano
      ```


1. Apply the resource to the cluster (if you have not edited the resource in-place using `kubectl edit`):

   ```shell
   kubectl apply -f my-verrazzano.yaml
   ```
   
1. Wait for the upgrade to complete:

   ```shell
   kubectl wait --timeout=20m --for=condition=UpgradeComplete verrazzano/my-verrazzano
   ```

## Verify the Upgrade

Verrazzano installs multiple objects in multiple namespaces. In the `verrazzano-system` namespaces, all the pods in the `Running` state does not guarantee, but likely indicates that Verrazzano is up and running.

While the upgrade is in progress, you may see some pods terminating and restarting as newer versions of components are 
applied.

```
kubectl get pods -n verrazzano-system
verrazzano-admission-controller-84d6bc647c-7b8tl   1/1     Running   0          5m13s
verrazzano-cluster-operator-57fb95fc99-kqjll       1/1     Running   0          5m13s
verrazzano-monitoring-operator-7cb5947f4c-x9kfc    1/1     Running   0          5m13s
verrazzano-operator-b6d95b4c4-sxprv                1/1     Running   0          5m13s
vmi-system-api-7c8654dc76-2bdll                    1/1     Running   0          4m44s
vmi-system-es-data-0-6679cf99f4-9p25f              2/2     Running   0          4m44s
vmi-system-es-data-1-8588867569-zlwwx              2/2     Running   0          4m44s
vmi-system-es-ingest-78f6dfddfc-2v5nc              1/1     Running   0          4m44s
vmi-system-es-master-0                             1/1     Running   0          4m44s
vmi-system-es-master-1                             1/1     Running   0          4m44s
vmi-system-es-master-2                             1/1     Running   0          4m44s
vmi-system-grafana-5f7bc8b676-xx49f                1/1     Running   0          4m44s
vmi-system-kibana-649466fcf8-4n8ct                 1/1     Running   0          4m44s
vmi-system-prometheus-0-7f97ff97dc-gfclv           3/3     Running   0          4m44s
vmi-system-prometheus-gw-7cb9df774-48g4b           1/1     Running   0          4m44s
```


## Known Issues
