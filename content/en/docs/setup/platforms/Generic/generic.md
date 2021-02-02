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

{{< /tab >}}
{{< /tabs >}}

