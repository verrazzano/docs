---
linkTitle: OCI OKE
weight: 2
draft: false
---
### Prepare for the OCI install

- Create the OKE cluster using the OCI Console or some other means.

- For `KUBERNETES VERSION`, select `v1.16.8`.

- For `SHAPE`, an OKE cluster with 3 nodes of `VM.Standard2.4` OCI Compute instance shape has proven sufficient to install Verrazzano and deploy the Bob's Books example application.

- Set the following ENV vars:
```
  export KUBECONFIG=<path to valid Kubernetes config>
```

* Create the optional `imagePullSecret` named `verrazzano-container-registry`.  This step is required when one or more of the Docker images installed by Verrazzano are private.  For example, while testing a change to the `verrazzano-operator`, you may be using a Docker image that requires credentials to access it.

```
    kubectl create secret docker-registry verrazzano-container-registry --docker-username=<username> --docker-password=<password> --docker-server=<docker server>
```


