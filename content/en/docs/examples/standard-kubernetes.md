---
title: "Standard Kubernetes Resources"
weight: 6
description: "Example of using standard Kubernetes resources"
draft: false
---


This example demonstrates using standard Kubernetes resources, in conjunction with OAM resources, to define and deploy an application.
Several standard Kubernetes resources are used in this example, both as workloads and traits.  
- Deployment is used as a workload within a Component.
- Service is used as a workload within a Component.
- Ingress is used as a trait within an ApplicationConfiguration.

## Before you begin
Install Verrazzano by following the [installation]({{< relref "/docs/setup/install/" >}}) instructions.

### Grant permissions
The `oam-kubernetes-runtime` is not installed with privileges that allow it to create the Kubernetes Ingress resource used in this example.
The following steps create a role that allows Ingress resource creation and binds that role to the `oam-kubernetes-runtime` service account.
For this example to work, your cluster admin will need to run the following steps to create the ClusterRole and ClusterRoleBinding.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: oam-kubernetes-runtime-ingresses
rules:
  - apiGroups:
    - networking.k8s.io
    - extensions
    resources:
    - ingresses
    verbs:
    - create
    - delete
    - get
    - list
    - patch
    - update
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oam-kubernetes-runtime-ingresses
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: oam-kubernetes-runtime-ingresses
subjects:
  - kind: ServiceAccount
    name: oam-kubernetes-runtime
    namespace: verrazzano-system
EOF
```

</div>
{{< /clipboard >}}


## Deploy the application
This example provides a web application using a common example application image.
When accessed, the application returns the configured text.

1. Create the application namespace and add a label identifying the namespace as managed by Verrazzano.
{{< clipboard >}}
<div class="highlight">

   ```
    $ kubectl create namespace oam-kube
    $ kubectl label namespace oam-kube verrazzano-managed=true istio-injection=enabled
   ```

</div>
{{< /clipboard >}}


1. Create a Component containing a Deployment workload.
{{< clipboard >}}
<div class="highlight">

   ```
    $ kubectl apply -f - <<EOF
    apiVersion: core.oam.dev/v1alpha2
    kind: Component
    metadata:
      name: oam-kube-dep-comp
      namespace: oam-kube
    spec:
      workload:
        kind: Deployment
        apiVersion: apps/v1
        name: oam-kube-dep
        spec:
          replicas: 1
          selector:
            matchLabels:
              app: oam-kube-app
          template:
            metadata:
              labels:
                app: oam-kube-app
            spec:
              containers:
                - name: oam-kube-cnt
                  image: hashicorp/http-echo
                  args:
                    - "-text=hello"
    EOF
   ```

</div>
{{< /clipboard >}}

1. Create a Component containing a Service workload.
{{< clipboard >}}
<div class="highlight">

  ```
    $ kubectl apply -f - <<EOF
    apiVersion: core.oam.dev/v1alpha2
    kind: Component
    metadata:
      name: oam-kube-svc-comp
      namespace: oam-kube
    spec:
      workload:
        kind: Service
        apiVersion: v1
        metadata:
          name: oam-kube-svc
        spec:
          selector:
            app: oam-kube-app
          ports:
          - port: 5678 # Default port for image
    EOF
  ```

</div>
{{< /clipboard >}}

1. Create an ApplicationConfiguration referencing both Components and configuring an ingress trait.
{{< clipboard >}}
<div class="highlight">

  ```
    $ kubectl apply -f - <<EOF
    apiVersion: core.oam.dev/v1alpha2
    kind: ApplicationConfiguration
    metadata:
      name: oam-kube-appconf
      namespace: oam-kube
    spec:
      components:
        - componentName: oam-kube-dep-comp
        - componentName: oam-kube-svc-comp
          traits:
            - trait:
                apiVersion: networking.k8s.io/v1beta1
                kind: Ingress
                metadata:
                  name: oam-kube-ing
                  annotations:
                    kubernetes.io/ingress.class: istio
                spec:
                  rules:
                  - host: oam-kube-app.example.com
                    http:
                      paths:
                        - path: /example
                          backend:
                            serviceName: oam-kube-svc
                            servicePort: 5678
    EOF
   ```

</div>
{{< /clipboard >}}


## Explore the application
1. Get the host name for the application.
{{< clipboard >}}
<div class="highlight">

   ```
   $ export HOST=$(kubectl get ingress \
       -n oam-kube oam-kube-ing \
       -o jsonpath='{.spec.rules[0].host}')
   $ echo "HOST=${HOST}"
   ```

</div>
{{< /clipboard >}}

1. Get the load balancer address of the ingress gateway.
{{< clipboard >}}
<div class="highlight">

   ```
   $ export LOADBALANCER=$(kubectl get ingress \
       -n oam-kube oam-kube-ing \
       -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
   $ echo "LOADBALANCER=${LOADBALANCER}"
   ```

</div>
{{< /clipboard >}}

1. Access the application.
{{< clipboard >}}
<div class="highlight">

   ```
   $ curl http://${HOST}/example --resolve ${HOST}:80:${LOADBALANCER}

   # Expected response
   hello
   ```

</div>
{{< /clipboard >}}


## Undeploy the application
To undeploy the application, delete the namespace created.
This will result in the deletion of all explicitly and implicitly created resources in the namespace.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl delete namespace oam-kube
```

</div>
{{< /clipboard >}}

If desired, the cluster admin also can remove the created ClusterRole and ClusterRoleBinding.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl delete ClusterRoleBinding oam-kubernetes-runtime-ingresses
$ kubectl delete ClusterRole oam-kubernetes-runtime-ingresses
```

</div>
{{< /clipboard >}}
