---
title: "Customize Istio"
description: "Customize Istio Gateways"
linkTitle: Istio
weight: 6
draft: false
---

Verrazzano uses Istio to provide application ingress as well as to facilitate mutual TLS authentication (mTLS) cluster communication.
You can customize the Verrazzano Istio component using settings in the Verrazzano custom resource.

The following table describes the fields in the Verrazzano custom resource pertaining to the [Istio component]({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#istio-component" >}}).

| Path to Field                                       | Description |
| --- | --- |
| `spec.components.istio.egress.kubernetes.replicas`  | The number of pods to replicate.  The default is `2` for the `prod` profile and `1` for all other profiles. |
| `spec.components.istio.egress.kubernetes.affinity`  | The pod affinity definition expressed as a standard Kubernetes [affinity](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#affinity-and-anti-affinity) definition.  The default configuration spreads the Istio gateway pods across the available nodes. <pre>spec:<br>  components:<br>    istio:<br>      egress:<br>        kubernetes:<br>          affinity:<br>            podAntiAffinity:<br>              preferredDuringSchedulingIgnoredDuringExecution:<br>                - weight: 100<br>                  podAffinityTerm:<br>                    labelSelector:<br>                      matchExpressions:<br>                        - key: app<br>                          operator: In<br>                          values:<br>                            - istio-egressgateway<br>                    topologyKey: kubernetes.io/hostname</pre>  |
| `spec.components.istio.ingress.kubernetes.replicas` | The number of pods to replicate.  The default is `2` for the `prod` profile and `1` for all other profiles. |
| `spec.components.istio.ingress.kubernetes.affinity` | The pod affinity definition expressed as a standard Kubernetes [affinity](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#affinity-and-anti-affinity) definition.  The default configuration spreads the Istio gateway pods across the available nodes. <pre>spec:<br>  components:<br>    istio:<br>      ingress:<br>        kubernetes:<br>          affinity:<br>            podAntiAffinity:<br>              preferredDuringSchedulingIgnoredDuringExecution:<br>                - weight: 100<br>                  podAffinityTerm:<br>                    labelSelector:<br>                      matchExpressions:<br>                        - key: app<br>                          operator: In<br>                          values:<br>                            - istio-ingressgateway<br>                    topologyKey: kubernetes.io/hostname</pre> |

The following example customizes a Verrazzano `prod` profile as follows:
* Increases the replicas count to `3` for `istio-ingressgateway` and `istio-egressgateway`
* Changes the `podAffinity` configuration to use `requiredDuringSchedulingIgnoredDuringExecution` for `istio-ingressgateway` and `istio-egressgateway`

 ```
 apiVersion: install.verrazzano.io/v1alpha1
 kind: Verrazzano
 metadata:
   name: example-verrazzano
 spec:
   profile: prod
   components:
     istio:
       ingress:
         kubernetes:
           replicas: 3
           affinity:
             podAntiAffinity:
               requiredDuringSchedulingIgnoredDuringExecution:
                 - weight: 25
                     labelSelector:
                       matchExpressions:
                         - key: app
                           operator: In
                           values:
                             - istio-ingressgateway
                     topologyKey: kubernetes.io/hostname
       egress:
         kubernetes:
           replicas: 3
           affinity:
             podAntiAffinity:
               requiredDuringSchedulingIgnoredDuringExecution:
                 - labelSelector:
                     matchExpressions:
                       - key: app
                         operator: In
                         values:
                           - istio-egressgateway
                   topologyKey: kubernetes.io/hostname
 ```

You can also customize Istio using [Overrides](({{< relref "/docs/reference/API/Verrazzano/Verrazzano.md#override" >}})).
To do this, define an IstioOperator resource to be passed in as an override. The following example overrides the shape
of an Oracle Cloud Infrastructure load balancer used by Istio for the ingress gateway.
```yaml
apiVersion: install.verrazzano.io/v1alpha1
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
              ingressGateways:
              - name: istio-ingressgateway
                k8s:
                  serviceAnnotations:
                    service.beta.kubernetes.io/oci-load-balancer-shape: 10Mbps
```

When overriding values in the ingress gateway or the egress gateway, it is necessary to specify the name,
so either `istio-ingressgateway`, or `istio-egressgateway`.

Verrazzano can accept any valid IstioOperator Custom Resource as an override. You can reference the IstioOperator API
in the [istio.io/api/operator/v1alpha1 package](https://pkg.go.dev/istio.io/api/operator/v1alpha1).