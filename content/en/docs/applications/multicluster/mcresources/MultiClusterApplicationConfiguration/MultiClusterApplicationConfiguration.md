---
title: MultiClusterApplicationConfiguration
linkTitle: "MultiClusterApplicationConfiguration"
weight: 4
draft: false
---
The [MultiClusterApplicationConfiguration]({{< relref "/docs/reference/vao-clusters-v1alpha1#clusters.verrazzano.io/v1alpha1.MultiClusterApplicationConfiguration" >}}) custom resource is an envelope used to distribute `core.oam.dev/v1alpha2/ApplicationConfiguration` resources in a multicluster environment.

Here is a sample MultiClusterApplicationConfiguration that specifies an ApplicationConfiguration resource to create on the cluster named `managed1`.  To deploy an example application that demonstrates a MultiClusterApplicationConfiguration, see [Multicluster ToDo List]({{< relref "/docs/examples/multicluster/todo-list/" >}}).

{{< clipboard >}}
<div class="highlight">

    apiVersion: clusters.verrazzano.io/v1alpha1
    kind: MultiClusterApplicationConfiguration
    metadata:
      name: todo-appconf
      namespace: mc-todo-list
    spec:
      template:
        metadata:
          annotations:
            version: v1.0.0
            description: "ToDo List example application"
        spec:
          components:
            - componentName: todo-domain
              traits:
                - trait:
                    apiVersion: oam.verrazzano.io/v1alpha1
                    kind: MetricsTrait
                - trait:
                    apiVersion: oam.verrazzano.io/v1alpha1
                    kind: IngressTrait
                    spec:
                      rules:
                        - paths:
                            - path: "/todo"
                              pathType: Prefix
            - componentName: todo-jdbc-config
            - componentName: mysql-initdb-config
            - componentName: todo-mysql-service
            - componentName: todo-mysql-deployment
      placement:
        clusters:
          - name: managed1
      secrets:
        - tododomain-repo-credentials
        - tododomain-jdbc-tododb
        - tododomain-weblogic-credentials

</div>
{{< /clipboard >}}
