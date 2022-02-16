---
title: "Customize Istio"
description: "Customize Istio Gateways"
linkTitle: Istio
weight: 2
draft: false
---

Verrazzano Istio gateways can be customized for High Availability by specifying replicas and affinity.

The default affinity configuration for all installation profiles is to allocate a replica to each node using podAntiAffinity.
The example below is for the ingress gateway
```aidl
            podAntiAffinity:
              preferredDuringSchedulingIgnoredDuringExecution:
                - weight: 100
                  podAffinityTerm:
                    labelSelector:
                      matchExpressions:
                        - key: app
                          operator: In
                          values:
                            - istio-ingressgateway
                    topologyKey: kubernetes.io/hostname
```
The default gateway (ingress and egress) pod replicas are
* Prod Profile                -   2 replicas of each gateway
* Dev/Managed-cluster Profile -   1 replica of each gateway

The following is an example of overriding the defaults in a verrazzano yaml
```aidl
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: istio-overrides
spec:
  profile: dev
  components:
    istio:
      enabled: true
      ingress:
        kubernetes:
          replicas: 3
          affinity:
            podAffinity: {}
            podAntiAffinity:
              preferredDuringSchedulingIgnoredDuringExecution:
                - weight: 25
                  podAffinityTerm:
                    labelSelector:
                      matchExpressions:
                        - key: app
                          operator: In
                          values:
                            - istio-ingressgateway
                    topologyKey: kubernetes.io/hostname
      egress:
        kubernetes:
          replicas: 4
          affinity:
            podAffinity: {}
            podAntiAffinity:
              preferredDuringSchedulingIgnoredDuringExecution:
                - weight: 75
                  podAffinityTerm:
                    labelSelector:
                      matchExpressions:
                        - key: app
                          operator: In
                          values:
                            - istio-egressgateway
                    topologyKey: kubernetes.io/hostname
```