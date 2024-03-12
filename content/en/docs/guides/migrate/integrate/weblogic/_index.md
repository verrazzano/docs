---
title: "WebLogic Kubernetes Operator"
weight: 1
draft: false
---
This document shows you how to integrate WebLogic Kubernetes Operator with other OCNE components.

## Fluent Bit
Follow the example, [Configure the namespace ConfigSelector]({{< relref "docs/guides/migrate/install/fluent/_index.md#configure-the-namespace-configselector" >}}), to add a Helm override for the namespace config label selector.

Then, apply the following manifest file in your cluster. Replace `<namespace-name>` with the namespace in which weblogic-kubernetes-operator is installed and `metadata.labels` of the FluentBitConfig custom resource with the namespace config selector Helm override supplied in the previous step.

**Note**: The following manifest file assumes that the namespace config label selector override was `my.label.selector/namespace-config: "mylabel"`.

**fo_wls.yaml**
{{< clipboard >}}
<div class="highlight">

```
apiVersion: fluentbit.fluent.io/v1alpha2
kind: FluentBitConfig
metadata:
  labels:
    my.label.selector/namespace-config: "mylabel"  
  name: weblogic-fbc
  namespace: <namespace_name>
spec:
  filterSelector:
    matchLabels:
      fluentbit.fluent.io/component: "weblogic"
  parserSelector:
    matchLabels:
      fluentbit.fluent.io/component: "weblogic"
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Filter
metadata:
  labels:
    fluentbit.fluent.io/component: "weblogic"
  name: weblogic-filter
  namespace: <namespace_name>
spec:
  filters:
    - parser:
        keyName: log
        reserveData: true
        preserveKey: true
        parser: weblogic-parser
    - recordModifier:
        removeKeys:
          - timestamp
  match: 'kube.*weblogic-operator*_weblogic-operator*'
---
apiVersion: fluentbit.fluent.io/v1alpha2
kind: Parser
metadata:
  labels:
    fluentbit.fluent.io/component: "weblogic"
  name: weblogic-parser
  namespace: <namespace_name>
spec:
  json:
    timeKey: logtime
    timeKeep: true
    timeFormat: "%Y-%m-%dT%H:%M:%S.%LZ"
```

</div>
{{< /clipboard >}}

## Network policies
The following NetworkPolicy must be created in the `weblogic-operator` namespace. This NetworkPolicy for a WebLogic Kubernetes Operator pod allows the following:

- Ingress traffic to any port from the `istio-system` namespace.
- Ingress traffic to Envoy port `15090` from the Prometheus pod in the `verrazzano-monitoring` namespace.
- Egress traffic is not restricted.

{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -n weblogic-operator -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: weblogic-operator
  namespace: weblogic-operator
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: istio-system
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
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
EOF
```
</div>
{{< /clipboard >}}

## Migrate OAM WebLogic applications to OCNE 2.0
For the migration, each OAM WebLogic application must be moved from the Verrazzano environment to the OCNE 2.0 environment. You will need to redeploy each OAM application in OCNE 2.0 without using OAM. This process is described in [OAM to Kubernetes Mappings]({{< relref "/docs/guides/migrate/oam-to-kubernetes/_index.md" >}}).

For each OAM application, start with the following command in your Verrazzano environment.

{{< clipboard >}}
<div class="highlight">

```
$ vz export oam --name <app-name> --namespace <app-namespace> > myapp.yaml
```
</div>
{{< /clipboard >}}

This generates a YAML file for the OAM application in `myapp.yaml`. Make any local customizations to the generated YAML file, and then apply the YAML file to the OCNE 2.0 environment by continuing to follow the documentation.
