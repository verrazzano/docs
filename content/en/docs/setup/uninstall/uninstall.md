---
title: "Uninstall"
linkTitle: "Uninstall"
description: "How to uninstall Verrazzano"
weight: 5
draft: false
---


To delete a Verrazzano installation, delete the Verrazzano custom resource you used to
install it into your cluster.

The following example starts a deletion of a Verrazzano installation in the background, and then
uses the `kubectl logs -f` command to tail the Console output of the pod performing the uninstall:

```
# Get the name of the Verrazzano custom resource
$ MYVZ=$(kubectl  get vz -o jsonpath="{.items[0].metadata.name}")

# Delete the Verrazzano custom resource
$ kubectl delete verrazzano $MYVZ --wait=false
$ kubectl logs -n verrazzano-install \
    -f $(kubectl get pod \
    -n verrazzano-install \
    -l job-name=verrazzano-uninstall-${MYVZ} \
    -o jsonpath="{.items[0].metadata.name}")
```
{{% alert title="NOTE" color="warning" %}}
Verrazzano requires `PersistentVolumes` for several of its components. These `PersistentVolumes` are recycled by Kubernetes. As explained in this [link](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#recycle), some Kubernetes platforms like [OLCNE](/docs/setup/platforms/OLCNE/OLCNE.md) can have a custom recycle Pod defined. This Pod could require access to images which may not be available to the environment. For example in case of [local registry setup](/docs/setup/private-registry/private-registry/) without access to public internet, the Pod defined in the preceding link will fail to start because it will not be able to pull the public `k8s.gcr.io/busybox` image. In such cases, it is required to have the specified container image locally on the Kubernetes node or in the local registry and use the argument `--pv-recycler-pod-template-filepath-nfs` to specify a custom pod template for the recycler. 
For example, to configure the recycler pod template on an OLCNE based Verrazzano cluster,
1. Configure the the recycler pod template as a `ConfigMap` entry.
    ```
    apiVersion: v1
    kind: ConfigMap
    metadata:
    name: recycler-pod-config
    namespace: kube-system
    data:
    recycler-pod.yaml: |
        apiVersion: v1
        kind: Pod
        metadata:
        name: pv-recycler
        namespace: default
        spec:
        restartPolicy: Never
        volumes:
        - name: vol
            hostPath:
            path: /any/path/it/will/be/replaced
        containers:
        - name: pv-recycler
            # busybox image from local registry
            image: "local-registry/busybox"
            command: ["/bin/sh", "-c", "test -e /scrub && rm -rf /scrub/..?* /scrub/.[!.]* /scrub/*  && test -z \"$(ls -A /scrub)\" || exit 1"]
            volumeMounts:
            - name: vol
            mountPath: /scrub
    ```
2. Edit the `kube-controller-manager` Pod in `kube-system` namespace.
    ```
    kubectl edit pod kube-controller-manager-xxxxx -n kube-system
    ```
3. Add the `recycler-pod-config` as a `volume` and the `recycler-pod.yaml` as a `volumeMount` to the `kube-controller-manager` pod. Also add the `--pv-recycler-pod-template-filepath-nfs` with value as path to `recycler-pod.yaml` in the pod.
    ```
    apiVersion: v1
    kind: Pod
    ...
    spec:
    containers:
    - command:
        - kube-controller-manager
        - --allocate-node-cidrs=true
        ...
        - --pv-recycler-pod-template-filepath-nfs=/etc/recycler-pod.yaml
        ...
        volumeMounts:
        ...
        - name: recycler-config-volume
        mountPath: /etc/recycler-pod.yaml
        subPath: recycler-pod.yaml   
    ...
    volumes:
    ...
    - name: recycler-config-volume
        configMap:
            name: recycler-pod-config
    ``` 
{{% /alert %}}