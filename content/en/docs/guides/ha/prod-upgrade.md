---
title: "Upgrade prod Installation for High Availability"
linkTitle: "Upgrade prod Installation"
description: "A guide for upgrading a `prod` installation for a highly available environment"
weight: 3
draft: false
---

The exact steps required to upgrade a Verrazzano environment to achieve high availability will vary based on the configuration of each environment.

1. Assess whether your Kubernetes configuration must be updated to support the level of high availability that you want to achieve.  See [Configure High Availability]({{< relref "/docs/guides/ha/ha.md" >}}).

1. Upgrade Verrazzano to v1.5.0 or later.   See [Upgrade Verrazzano]({{< relref "/docs/setup/upgrade/_index.md" >}}).

1. The [examples/ha]({{< ghlink path="examples/ha/README.md" >}}) directory contains examples of highly available Verrazzano installations. The following example uses the [ha.yaml]({{< ghlink raw=true path="examples/ha/ha.yaml" >}}) file as an example of how to upgrade a default `prod` installation to a highly available Verrazzano environment.

   a. Create a patch file:

{{< clipboard >}}
<div class="highlight">

   ```
   $ cat > patch.yaml <<EOF
   spec:
     components:
       authProxy:
         overrides:
         - values:
             replicas: 2
       certManager:
         overrides:
         - values:
             replicaCount: 2
             cainjector:
               replicaCount: 2
             webhook:
               replicaCount: 2
       console:
         overrides:
         - values:
             replicas: 2
       ingress:
         overrides:
         - values:
             controller:
               autoscaling:
                 enabled: true
                 minReplicas: 2
             defaultBackend:
               replicaCount: 2
       istio:
         overrides:
         - values:
             apiVersion: install.istio.io/v1alpha1
             kind: IstioOperator
             spec:
               components:
                 pilot:
                   k8s:
                     replicaCount: 2
                 ingressGateways:
                   - enabled: true
                     k8s:
                       affinity:
                         podAntiAffinity:
                           preferredDuringSchedulingIgnoredDuringExecution:
                           - podAffinityTerm:
                               labelSelector:
                                 matchExpressions:
                                 - key: app
                                   operator: In
                                   values:
                                   - istio-ingressgateway
                               topologyKey: kubernetes.io/hostname
                             weight: 100
                       replicaCount: 2
                       service:
                         type: LoadBalancer
                     name: istio-ingressgateway
                 egressGateways:
                   - enabled: true
                     k8s:
                       affinity:
                         podAntiAffinity:
                           preferredDuringSchedulingIgnoredDuringExecution:
                           - podAffinityTerm:
                               labelSelector:
                                 matchExpressions:
                                 - key: app
                                   operator: In
                                   values:
                                   - istio-egressgateway
                               topologyKey: kubernetes.io/hostname
                             weight: 100
                       replicaCount: 2
                     name: istio-egressgateway
       keycloak:
         overrides:
         - values:
             replicas: 2
         mysql:
           overrides:
           - values:
               serverInstances: 3
               routerInstances: 2
       opensearchDashboards:
         replicas: 2
       kiali:
         overrides:
         - values:
             deployment:
               replicas: 2
       prometheusOperator:
         overrides:
         - values:
             prometheus:
               prometheusSpec:
                 replicas: 2
       opensearch:
         nodes:
         - name: es-ingest
           replicas: 2
   EOF
   ```

</div>
{{< /clipboard >}}

   b. Apply the patch:
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl patch verrazzano verrazzano --patch-file=patch.yaml --type=merge
   ```

</div>
{{< /clipboard >}}


   c. Wait for the patch to be installed:
{{< clipboard >}}
<div class="highlight">

   ```
   $ kubectl wait --timeout=30m --for=jsonpath='{.status.state}'=Ready verrazzano/verrazzano
   ```

</div>
{{< /clipboard >}}
