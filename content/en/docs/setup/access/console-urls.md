---
title: Get Console URLs
description: "Get the endpoints for the consoles that Verrazzano installs"
weight: 2
draft: false
---

You can access the installation endpoints using the [Verrazzano CLI]({{< relref "/docs/setup/install" >}}) or with [kubectl](https://kubernetes.io/docs/reference/kubectl/kubectl/):

- [Verrazzano CLI](#verrazzano-cli)
- [kubectl](#kubectl)

### Verrazzano CLI

You can get the endpoints for these consoles by issuing the following command
and examining the `Status.Instance` field:

```shell
$ vz status
```

The resulting output is similar to the following:

```shell
Verrazzano Status
  Name: verrazzano
  Namespace: default
  Version: 1.5.0
  State: Ready
  Profile: dev
  Available Components: 24/24
  Access Endpoints:
    argoCDUrl: https://argocd.default.11.22.33.44.nip.io
    consoleUrl: https://verrazzano.default.11.22.33.44.nip.io
    grafanaUrl: https://grafana.vmi.system.default.11.22.33.44.nip.io
    jaegerURL: https://jaeger.default.11.22.33.44.nip.io
    keyCloakUrl: https://keycloak.default.11.22.33.44.nip.io
    kialiUrl: https://kiali.vmi.system.default.11.22.33.44.nip.io
    openSearchDashboardsUrl: https://osd.vmi.system.default.11.22.33.44.nip.io
    openSearchUrl: https://opensearch.vmi.system.default.11.22.33.44.nip.io
    prometheusUrl: https://prometheus.vmi.system.default.11.22.33.44.nip.io
    rancherUrl: https://rancher.default.11.22.33.44.nip.io
    thanosQueryUrl: https://thanos-query.default.11.22.33.44.nip.io
```

### kubectl

You can get the endpoints for these consoles by issuing the following command
and examining the `Status.Instance` field:
{{< clipboard >}}

```shell
$ kubectl get vz -o yaml
```
{{< /clipboard >}}



The resulting output is similar to the following (abbreviated to show only the relevant portions):

{{< clipboard >}}
<div class="highlight">

```
  ...
  status:
    conditions:
    - lastTransitionTime: "2021-06-30T03:10:00Z"
      message: Verrazzano install in progress
      status: "True"
      type: InstallStarted
    - lastTransitionTime: "2021-06-30T03:18:33Z"
      message: Verrazzano install completed successfully
      status: "True"
      type: InstallComplete
    instance:
      argoCDUrl: https://argocd.default.11.22.33.44.nip.io
      consoleUrl: https://verrazzano.default.11.22.33.44.nip.io
      grafanaUrl: https://grafana.vmi.system.default.11.22.33.44.nip.io
      keyCloakUrl: https://keycloak.default.11.22.33.44.nip.io
      kialiUrl: https://kiali.vmi.system.default.11.22.33.44.nip.io
      opensearchDashboardsUrl: https://osd.vmi.system.default.11.22.33.44.nip.io
      opensearchUrl: https://opensearch.vmi.system.default.11.22.33.44.nip.io
      prometheusUrl: https://prometheus.vmi.system.default.11.22.33.44.nip.io
      rancherUrl: https://rancher.default.11.22.33.44.nip.io
      thanosQueryUrl: https://thanos-query.default.11.22.33.44.nip.io
```
</div>
{{< /clipboard >}}


If you have `jq` installed, then you can use the following command to get the instance URLs more directly.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl get vz -o jsonpath="{.items[].status.instance}" | jq .
```

</div>
{{< /clipboard >}}

The following is an example of the output:

```
{
"argoCDUrl": https://argocd.default.11.22.33.44.nip.io
"consoleUrl": "https://verrazzano.default.11.22.33.44.nip.io",
"grafanaUrl": "https://grafana.vmi.system.default.11.22.33.44.nip.io",
"keyCloakUrl": "https://keycloak.default.11.22.33.44.nip.io",
"kialiUrl": "https://kiali.vmi.system.default.11.22.33.44.nip.io",
"opensearchUrl": "https://opensearch.vmi.system.default.11.22.33.44.nip.io",
"opensearchDashboardsUrl": "https://osd.vmi.system.default.11.22.33.44.nip.io",
"prometheusUrl": "https://prometheus.vmi.system.default.11.22.33.44.nip.io",
"rancherUrl": "https://rancher.default.11.22.33.44.nip.io"
"thanosQueryUrl": "https://thanos-query.default.11.22.33.44.nip.io"
}
```
