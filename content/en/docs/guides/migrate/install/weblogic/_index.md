---
title: "WebLogic Kubernetes Operator"
weight: 1
draft: false
---
This document shows you how to install WebLogic Kubernetes Operator on OCNE.

## Helm Install

With Verrazzano, the WebLogic Kubernetes Operator Helm chart used for installation and upgrade is embedded in the VPO image in a known location (`/verrazzano/platform-operator/thirdparty/charts/weblogic-operator`).

The following table shows the names and values used when installing and upgrading the WebLogic Kubernetes Operator Helm chart with Verrazzano.

| Name                      | Value                                                | Description                                               |
|---------------------------|------------------------------------------------------|-----------------------------------------------------------|
| `annotations`                | `traffic.sidecar.istio.io/excludeOutboundPorts: 443`  | Outbound port to be excluded from redirection to Envoy.    |
| `domainNamespaceLabelSelector` | `verrazzano-managed`  | Label selector used when searching for namespaces that the WebLogic Kubernetes Operator will manage. `weblogic-operator=enabled` is the default value.  |
| `domainNamespaceSelectionStrategy`  | `LabelSelector`  | The WebLogic Kubernetes Operator will manage namespaces with Kubernetes labels that match the label selector defined by `domainNamespaceLabelSelector`. `LabelSelector` is the default value.   |
| `enableClusterRoleBinding`  | `true`   | WebLogic Kubernetes Operator has permission to manage any namespace and can automatically manage a namespace that is added after the operator was last installed or upgraded.  The default value is `true`.  |
| `image`   | `ghcr.io/oracle/weblogic-kubernetes-operator:4.1.2`  | WebLogic Kubernetes Operator image.  Defaults to version of WebLogic Kubernetes Operator Helm Chart.  |
| `serviceAccount`	  | `weblogic-operator-sa`  | Service account to be used by the WebLogic Kubernetes Operator.  |

### How Verrazzano installs the WebLogic Kubernetes Operator

To install the WebLogic Kubernetes Operator:

{{< clipboard >}}
<div class="highlight">

```
$ kubectl create namespace verrazzano-system
$ kubectl label namespace verrazzano-system verrazzano-managed=true istio-injection=enabled
$ kubectl create serviceaccount weblogic-operator-sa -n verrazzano-system
$ helm install weblogic-operator /verrazzano/platform-operator/thirdparty/charts/weblogic-operator -n verrazzano-system -f <helmValues>
```
</div>
{{< /clipboard >}}

In addition to the previous installation steps, a network policy is created for the WebLogic Kubernetes Operator.

The verrazzano-network-policies Helm chart creates the following network policy.

{{< clipboard >}}
<div class="highlight">

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: weblogic-operator
  namespace: verrazzano-system
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: istio-system
  - from:
    - namespaceSelector:
        matchLabels:
          verrazzano.io/namespace: verrazzano-monitoring
      podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
    ports:
    - port: 15090
      protocol: TCP
  podSelector:
    matchLabels:
      app: weblogic-operator
  policyTypes:
  - Ingress
```
</div>
{{< /clipboard >}}

The network policy for a WebLogic Kubernetes Operator pod allows the following:

- Allows ingress traffic to any port from the `istio-system` namespace
- Allows ingress traffic to envoy port 15090 from the Prometheus pod in the `verrazzano-monitoring` namespace
- Egress traffic is not restricted

## WebLogic Kubernetes Operator with OCNE 2.0

For OCNE 2.0, the WebLogic Kubernetes Operator will be installed and upgraded with the community version of its Helm chart.

To get the WebLogic Kubernetes Operator Helm chart downloaded and ready for installation or upgrade:

{{< clipboard >}}
<div class="highlight">

```
$ helm repo add weblogic-operator https://oracle.github.io/weblogic-kubernetes-operator/charts
$ helm repo update
```
</div>
{{< /clipboard >}}

To see what versions of the WebLogic Kubernetes Operator are available:

{{< clipboard >}}
<div class="highlight">

```
$ helm search repo weblogic-operator/weblogic-operator --versions
```
</div>
{{< /clipboard >}}

### How to install WebLogic Kubernetes Operator with OCNE 2.0
To see what Helm values were used when installing the WebLogic Kubernetes Operator in Verrazzano:

{{< clipboard >}}
<div class="highlight">

```
$ helm get values weblogic-operator -n verrazzano-system
```
</div>
{{< /clipboard >}}

**NOTES**: About installing the WebLogic Kubernetes Operator in OCNE 2.0:

- The WebLogic Kubernetes Operator runs within the Istio service mesh.
- Domains managed by the WebLogic Kubernetes Operator will reside in namespaces with the label `weblogic-operator=enabled`.  Namespaces will need to be labeled as needed.
- There is no need to specify the `domainNamespaceLabelSelector` Helm value.  The default value of `weblogic-operator=enabled` will be used.
- There is no need to specify the `domainNamespaceSelectionStrategy` Helm value. The default Helm value `LabelSelector` will be used.
- There is no need to specify the `enableClusterRoleBinding` Helm value. The default Helm value `true` will be used.
- The image Helm default value for the version of the WebLogic Kubernetes Operator can be used unless you want to override it.  For example, for an disconnected environment, you would override it.
- The `weblogicMonitoringExporterImage` Helm value is obsolete and is not needed.

**Example**: Installing WebLogic Kubernetes Operator 4.1.7 in OCNE 2.0.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl create namespace weblogic-operator
$ kubectl label namespace weblogic-operator istio-injection=enabled
$ kubectl create serviceaccount weblogic-operator-sa -n weblogic-operator

$ helm install weblogic-operator weblogic-operator/weblogic-operator -n weblogic-operator --version=4.1.7 -f - <<EOF
annotations:
  traffic.sidecar.istio.io/excludeOutboundPorts: '443'
serviceAccount: weblogic-operator-sa
# specify image if you want to override the default WebLogic Kubernetes Operator image
# image: <weblogic-operator-image>
#
# add any custom Helm values specified when installing Verrazzano
# nodeSelector:
#   node-type: fc-csi
EOF
```
</div>
{{< /clipboard >}}

## Migrate OAM WebLogic applications to OCNE 2.0
As part of the migration, each OAM WebLogic application needs to be moved from the Verrazzano environment to the OCNE 2.0 environment. You will need to redeploy each OAM application in OCNE 2.0 without using OAM. This process is described in [OAM to Kubernetes Mappings]({{< relref "/docs/guides/migrate/oam-to-kubernetes/_index.md" >}}).

For each OAM application, start with the following command in your Verrazzano environment.

{{< clipboard >}}
<div class="highlight">

```
$ vz export oam --name <app-name> --namespace <app-namespace> > myapp.yaml
```
</div>
{{< /clipboard >}}

This generates a YAML file for the OAM application in `myapp.yaml`. Make any local customizations to the generated YAML file, and then apply the YAML file to the OCNE 2.0 environment by continuing to follow the documentation.
