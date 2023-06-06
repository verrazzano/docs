---
title: "Installation Overrides"
description: "Customize installation overrides"
weight: 6
draft: false
---

Installation overrides let you supply custom values to the underlying Helm charts or operator for a given component.
You can supply Verrazzano installation overrides by using a `configMapRef`, `secretRef`, or raw `values`.

The following tables have examples of the Istio component InstallOverrides [ConfigMap](#configmap), [Secret](#secret), and [Values](#values), where the external IP addresses are specified instead of using the defaults. For the default values, see the [IstioOperatorSpec](https://istio.io/v1.13/docs/reference/config/istio.operator.v1alpha1/#IstioOperatorSpec).

In the examples, the ConfigMap and Secret overrides are applied before applying the Verrazzano resource installation YAML file.

## ConfigMap

Note that the value of the `metadata` `name` in the `configMap.yaml` file must match the `configMapRef` `name` in the `verrazzanoResourceWithConfigMapRef.yaml` file. Also, the values of the `key` in the `configMapRef` and the key in the `data` section of the `configMap` must match.
<table>
   <thead>
      <tr>
         <th>ConfigMap<br><code>configMap.yaml</code></th>
         <th>ConfigMapRef<br><code>verrazzanoResourceWithConfigMapRef.yaml</code></th>
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
              - 11.22.33.44
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

## Secret
<table>
   <thead>
      <tr>
         <th>Secret<br><code>secret.yaml</code></th>
         <th>SecretRef<br><code>verrazzanoResourceWithSecretRef.yaml</code></th>
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
              - 11.22.33.44
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

## Values
<table>
   <thead>
      <tr>
         <th>Values<br><code>verrazzanoResourceWithValues.yaml</code></th>
      </tr>
   </thead>
   <tr>
      <td>
{{< clipboard >}}
```yaml
apiVersion: install.verrazzano.io/v1beta1
kind: Verrazzano
metadata:
  name: vz-with-values
spec:
  components:
    istio:
      overrides:
      - values:
          apiVersion: install.istio.io/v1alpha1
          kind: IstioOperator
          spec:
            components:
              ingressGateways:
                - enabled: true
                  name: istio-ingressgateway
                  k8s:
                    service:
                      type: NodePort
                      ports:
                      - name: https
                        port: 443
                        nodePort: 32443
                        protocol: TCP
                        targetPort: 8443
                      externalIPs:
                      - 11.22.33.44
```
{{< /clipboard >}}
      </td>
   </tr>
</table>
