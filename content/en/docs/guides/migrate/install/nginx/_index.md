---
title: "NGINX Ingress Controller"
weight: 1
draft: false
---
This document shows you how to install NGINX Ingress Controller on OCNE.

Verrazzano installs [NGINX Ingress Controller](https://www.nginx.com/resources/glossary/kubernetes-ingress-controller/) to provide ingress to system components like Prometheus, OpenSearch, OpenSearch Dashboards, and such. The ingress controller watches the ingress resources and reconciles them, and configures the underlying Kubernetes load balancer to handle the service routing.

You specify chart overrides for the ingress-controller component in the Verrazzano custom resource under `.spec.components.ingressNGINX.overrides`.

## Install ingress-controller
**TBD**, ingress-controller will be installed as a first-class CNE module and not from the app catalog.

### Install NGINX Ingress Controller using Helm

This example assumes that you are using Helm version 3.2.0 or later.

1. Add the ingress-nginx Helm repository to the cluster.
{{< clipboard >}}
<div class="highlight">

```
$ helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
$ helm repo update
```
</div>
{{< /clipboard >}}

1. Install or upgrade the ingress-nginx Helm chart.

   The following example `helm` command installs NGINX Ingress Controller. The ingress controller can be installed in any namespace; this example installs the Helm chart in the `ingress-nginx` namespace.

{{< clipboard >}}
<div class="highlight">

```
$ helm upgrade --install ingress-controller ingress-nginx/ingress-nginx -n ingress-nginx --create-namespace --version <version of the chart> -f <values specified in a YAML file>
```
</div>
{{< /clipboard >}}
At a minimum, the YAML file used for the `-f` option needs to override the values for the controller image defined in `values.yaml` in the following format:
{{< clipboard >}}
<div class="highlight">

```
controller:
  name: controller
  image:
    registry: <container registry hosting the NGINX Ingress Controller image>
    image: <name of the image>
    tag: <image tag>
    digest: <image digest>
```
</div>
{{< /clipboard >}}


### Helm overrides recipes

The following recipes show you how to override certain ingress-controller default settings. These overrides should be put into a file and passed into `helm` using the `-f` option.

#### Install ingress-controller from a private registry
**TBD** - need OCNE module private registry example

#### Configure NGINX controller
Override one or more custom [configuration](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/) options to NGINX.

For example, apply the following overrides to set the log format for JSON output.

{{< clipboard >}}
<div class="highlight">

```
controller:
  config:
    log-format-escape-json: "true"
    log-format-upstream: '
      {
        "@timestamp": "$time_iso8601",
        "req_id": "$req_id",
        "proxy_upstream_name": "$proxy_upstream_name",
        "proxy_alternative_upstream_name": "$proxy_alternative_upstream_name",
        "upstream_status": "$upstream_status",
        "upstream_addr": "$upstream_addr",
        "message": "$request_method $host$request_uri",
        "http_request": {
          "requestMethod": "$request_method",
          "requestUrl": "$host$request_uri",
          "status": $status,
          "requestSize": "$request_length",
          "responseSize": "$upstream_response_length",
          "userAgent": "$http_user_agent",
          "remoteIp": "$remote_addr",
          "referer": "$http_referer",
          "latency": "$upstream_response_time s",
          "protocol":"$server_protocol"
        }
      }'
  ```
  </div>
  {{< /clipboard >}}

#### Configure custom IngressClasses
IngressClasses are used to fix the race condition in updating the status fields when multiple ingress controllers are deployed. For more information, see [Multiple Ingress controllers](https://kubernetes.github.io/ingress-nginx/user-guide/multiple-ingress/).

For example, apply the following overrides to create an IngressClass resource.

{{< clipboard >}}
<div class="highlight">

```
controller:
  ingressClass: my-nginx
  ingressClassByName: true
  ingressClassResource:
    name: my-nginx
    enabled: true
    default: false
    controllerValue: "k8s.io/my-ingress-nginx"
  ```
  </div>
  {{< /clipboard >}}

#### Configure pod and container security
Override pod and container security default settings to limit actions that pods and containers can perform in the cluster. These settings allow pods and containers to perform only operations that are needed for them to operate successfully, and to mitigate security vulnerabilities, such as privilege escalation.

For example, apply the following overrides when installing the ingress-controller module in an OCNE cluster to use security settings.

{{< clipboard >}}
<div class="highlight">

```
controller:
  podSecurityContext:
    runAsUser: 101
    runAsGroup: 101
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containerSecurityContext:
    allowPrivilegeEscalation: false
    capabilities:
      add:
        - NET_BIND_SERVICE
      drop:
        - ALL
    privileged: false
  ```
  </div>
  {{< /clipboard >}}

#### Configure Istio sidecar

When running the ingress controller in a cluster that also has Istio installed, define the `podAnnotations` for the controller as shown.

{{< clipboard >}}
<div class="highlight">

```
controller:
  podAnnotations:
    traffic.sidecar.istio.io/excludeInboundPorts: "80,443"
    traffic.sidecar.istio.io/includeInboundPorts: ""
    sidecar.istio.io/rewriteAppHTTPProbers: "true"
```
</div>
{{< /clipboard >}}
