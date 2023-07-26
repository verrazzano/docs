---
title: "Customize Istio"
description: "Customize Verrazzano Istio settings"
weight: 8
draft: false
aliases:
  - /docs/customize/istio
  - /docs/setup/customizing/istio
  - /docs/networking/istio
---

You can customize the Verrazzano Istio component using settings in the Verrazzano custom resource.

The following table describes the fields in the Verrazzano custom resource pertaining to the [Istio component]({{< relref "/docs/reference/vpo-verrazzano-v1beta1#install.verrazzano.io/v1beta1.IstioComponent" >}}).

| Path to Field                                       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| --- |-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `spec.components.istio.egress.kubernetes.replicas`  | The number of pods to replicate.  The default is `2` for the `prod` profile and `1` for all other profiles.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `spec.components.istio.egress.kubernetes.affinity`  | The pod affinity definition expressed as a standard Kubernetes [affinity](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#affinity-and-anti-affinity) definition.  The default configuration spreads the Istio gateway pods across the available nodes. <div class="highlight"><pre>spec:<br>  components:<br>    istio:<br>      egress:<br>        kubernetes:<br>          affinity:<br>            podAntiAffinity:<br>              preferredDuringSchedulingIgnoredDuringExecution:<br>                - weight: 100<br>                  podAffinityTerm:<br>                    labelSelector:<br>                      matchExpressions:<br>                        - key: app<br>                          operator: In<br>                          values:<br>                            - istio-egressgateway<br>                    topologyKey: kubernetes.io/hostname</pre></div>   |
| `spec.components.istio.ingress.kubernetes.replicas` | The number of pods to replicate.  The default is `2` for the `prod` profile and `1` for all other profiles.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `spec.components.istio.ingress.kubernetes.affinity` | The pod affinity definition expressed as a standard Kubernetes [affinity](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#affinity-and-anti-affinity) definition.  The default configuration spreads the Istio gateway pods across the available nodes. <div class="highlight"><pre>spec:<br>  components:<br>    istio:<br>      ingress:<br>        kubernetes:<br>          affinity:<br>            podAntiAffinity:<br>              preferredDuringSchedulingIgnoredDuringExecution:<br>                - weight: 100<br>                  podAffinityTerm:<br>                    labelSelector:<br>                      matchExpressions:<br>                        - key: app<br>                          operator: In<br>                          values:<br>                            - istio-ingressgateway<br>                    topologyKey: kubernetes.io/hostname</pre></div> |

The following example customizes a Verrazzano `prod` profile as follows:
* Increases the replicas count to `3` for `istio-ingressgateway` and `istio-egressgateway`
* Changes the `podAffinity` configuration to use `requiredDuringSchedulingIgnoredDuringExecution` for `istio-ingressgateway` and `istio-egressgateway`
{{< clipboard >}}
<div class="highlight">

 ```
 apiVersion: install.verrazzano.io/v1beta1
 kind: Verrazzano
 metadata:
   name: example-verrazzano
 spec:
   profile: prod
   components:
     istio:
       overrides:
       - values:
           apiVersion: install.istio.io/v1alpha1
           kind: IstioOperator
           spec:
             components:
               egressGateways:
                 - enabled: true
                   k8s:
                     affinity:
                       podAntiAffinity:
                         requiredDuringSchedulingIgnoredDuringExecution:
                           - podAffinityTerm:
                               labelSelector:
                                 matchExpressions:
                                   - key: app
                                     operator: In
                                     values:
                                       - istio-egressgateway
                               topologyKey: kubernetes.io/hostname
                             weight: 100
                     replicaCount: 3
                   name: istio-egressgateway
               ingressGateways:
                 - enabled: true
                   k8s:
                     affinity:
                       podAntiAffinity:
                         requiredDuringSchedulingIgnoredDuringExecution:
                           - podAffinityTerm:
                               labelSelector:
                                 matchExpressions:
                                   - key: app
                                     operator: In
                                     values:
                                       - istio-ingressgateway
                               topologyKey: kubernetes.io/hostname
                             weight: 100
                     replicaCount: 3
                     service:
                       type: LoadBalancer
                   name: istio-ingressgateway
 ```

</div>
{{< /clipboard >}}
