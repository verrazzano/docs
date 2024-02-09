---
title: "Ingress NGINX Controller"
weight: 1
draft: false
---
This document shows you how to install Ingress NGINX Controller on OCNE.

Verrazzano installs [NGINX Ingress Controller](https://www.nginx.com/resources/glossary/kubernetes-ingress-controller/), to provide ingress to system components like Prometheus, OpenSearch, OpenSearch Dashboards, etc.
The Ingress Controller watches the Ingress resources and reconcile them, configures the underlying Kubernetes load balancer to handle the service routing.

You specify chart overrides for the ingress-controller component in the Verrazzano custom resource under `.spec.components.ingressNGINX.overrides`.


## Install ingress-controller

### Installing ingress-controller using Helm
**TBD**, ingress-controller will be installed as a first-class CNE module and not from the app catalog.

For now, this document provides the instruction to install Ingress NGINX Controller using the Helm charts provided by the upstream.

1. Add the ingress-nginx Helm repository to the cluster:
{{< clipboard >}}
<div class="highlight">

```
$ helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
$ helm repo update
```
</div>
{{< /clipboard >}}

1. Install or upgrade the ingress-nginx Helm chart

   The following example `helm` command installs Ingress NGINX Controller. The Ingress Controller can be installed in any namespace, this example installs the Helm chart in `ingress-nginx` namespace. This example assumes you are using Helm version 3.2.0 or later.
{{< clipboard >}}
<div class="highlight">

```
$ helm upgrade --install ingress-controller ingress-nginx/ingress-nginx -n ingress-nginx --create-namespace --version <version of the chart> -f <values specified in a YAML file>
```
</div>
{{< /clipboard >}}
The YAML file used for option -f at minimum needs to override the values for the controller image defined in values.yaml in the following format:
{{< clipboard >}}
<div class="highlight">

```
controller:
  name: controller
  image:
    registry: <container registry hosting the Ingress NGINX Controller image>
    image: <name of the image>
    tag: <image tag>
    digest: <image digest>
```
</div>
{{< /clipboard >}}

The recipes below give examples of changing the configuration using Helm overrides.

### Helm Overrides recipes
The following sections show you how to override certain ingress-controller default settings. These overrides should be put into a file and passed into helm using the `-f` argument.

#### Installing from a private registry
**TBD** - need OCNE module private registry example

#### Configuring NGINX controller configuration
Override one or more custom [configuration](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/) options to NGINX.

For example, apply the following overrides to set the log format for json output.

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

#### Configuring custom IngressClasses
IngressClasses are used to fix the race condition in updating the status fields when multiple ingress controllers are deployed. Please refer to [Multiple Ingress controllers](https://kubernetes.github.io/ingress-nginx/user-guide/multiple-ingress/) for more details.

For example, apply the following overrides to create IngressClass resource

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

#### Configuring pod and container security
Override pod and container security default settings to limit actions that pods and containers can perform in the cluster. These settings allow pods and containers to perform only operations that are needed for them to operate successfully, and mitigate security vulnerabilities, such as privilege escalation.

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

#### Configuring Istio Sidecar

When running ingress controller in a cluster that also has Istio installed, define the `podAnnotations` for the controller as below:

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
