---
title: "Installation Overrides"
description: "Customize Install Overrides"
linkTitle: Installation Overrides
weight: 8
draft: false
---

You can customize Verrazzano Install Overrides by using a **ConfigMapRef**, **SecretRef**, or raw **Values**

The following table has examples of the [Istio component InstallOverrides]({{< relref "/docs/reference/API/vpo-verrazzano-v1beta1#install.verrazzano.io/v1beta1.InstallOverrides" >}}) ConfigMap and Secret, where the externalIPs is specified instead of using the defaults, that can be found [here](https://istio.io/v1.13/docs/reference/config/istio.operator.v1alpha1/#IstioOperatorSpec).

### Examples
In both examples the ConfigMap and Secret are a applied before applying the vz install yaml.
The **name** in both match as well as the **key** for the data section.

### ConfigMap ### 
<table>
   <thead>
      <tr>
         <th>ConfigMap<br><code>configMap.yaml</code></th>
         <th>ConfigMapRef<br><code>vzWithConfigMapRef.yaml</code></th>
      </tr>
   </thead>
<tr>
<td>
{{< clipboard >}}
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: istio-cm
data:
  istio-override: |
    apiVersion: install.istio.io/v1alpha1
    kind: IstioOperator
    spec:
      components:
        ingressGateways:
        - k8s:
            service:
              externalIPs:
              - 11.22.33.55
              type: NodePort
          name: istio-ingressgateway 
```
{{< /clipboard >}}
</td>
<td>
{{< clipboard >}}
```yaml
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: vz-with-cm
spec:
  profile: dev
  components:
    rancher:
      enabled: false
    istio:
      overrides:
      -  configMapRef:
           name: istio-cm
           key: istio-override
```
{{< /clipboard >}}
</td>
</tr>
</table>

### Secret ### 
<table>
   <thead>
      <tr>
         <th>Secret<br><code>secret.yaml</code></th>
         <th>SecretRef<br><code>vzWithSecretRef.yaml</code></th>
      </tr>
   </thead>
   <tr>
      <td>
{{< clipboard >}}
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: istio-s
stringData:
  istio-override: |
    apiVersion: install.istio.io/v1alpha1
    kind: IstioOperator
    spec:
      components:
        ingressGateways:
        - k8s:
            service:
              externalIPs:
              - trashIP
              type: NodePort
          name: istio-ingressgateway         
```
{{< /clipboard >}}
      </td>
      <td>
{{< clipboard >}}
```yaml
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: vz-with-secret
  namespace: default
spec:
  profile: dev
  components:
    rancher:
      enabled: false
    istio:
      overrides:
      -  secretRef:
           name: istio-s
           key: istio-override
```
{{< /clipboard >}}
      </td>
   </tr>
</table>