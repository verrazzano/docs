---
title: Verrazzano Workloads
weight: 2
draft: false
---

### VerrazzanoCoherenceWorkload
The VerrazzanoCoherenceWorkload custom resource contains the configuration information for a [Coherence](https://oracle.github.io/coherence-operator/docs/3.1.3/#/about/04_coherence_spec) workload within Verrazzano.  Here is a sample component that specifies a VerrazzanoCoherenceWorkload.  To deploy an example application that demonstrates this workload type, see [Sock Shop]({{< relref "docs/samples/sock-shop.md" >}}).
```
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: carts
  namespace: sockshop
spec:
  workload:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoCoherenceWorkload
    spec:
      template:
        metadata:
          name: carts-coh
        spec:
          cluster: SockShop
          role: Carts
          replicas: 1
          image: ghcr.io/helidon-sockshop/carts-coherence:2.2.0
          imagePullPolicy: Always
          application:
            type: helidon
          jvm:
            args:
              - "-Dcoherence.k8s.operator.health.wait.dcs=false"
              - "-Dcoherence.metrics.legacy.names=false"
            memory:
              heapSize: 2g
          coherence:
            logLevel: 9
          ports:
            - name: http
              port: 7001
              service:
                name: carts
                port: 80
              serviceMonitor:
                enabled: true
            - name: metrics
              port: 7001
              serviceMonitor:
                enabled: true
```

#### VerrazzanoCoherenceWorkload

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `oam.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | VerrazzanoCoherenceWorkload |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `spec` |  [VerrazzanoCoherenceWorkloadSpec](#verrazzanocoherenceworkloadspec) | The desired state of a Verrazzano Coherence workload. |  Yes |


#### VerrazzanoCoherenceWorkloadSpec
VerrazzanoCoherenceWorkloadSpec specifies the desired state of a Verrazzano Coherence workload.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `template` |  [RawExtension](https://pkg.go.dev/k8s.io/apimachinery/pkg/runtime#RawExtension) | The metadata and spec for the underlying [Coherence](https://oracle.github.io/coherence-operator/docs/3.1.3/#/about/04_coherence_spec) resource. |  Yes |



### VerrazzanoHelidonWorkload

The VerrazzanoHelidonWorkload custom resource contains the configuration information for a [Helidon](https://helidon.io) workload within Verrazzano. Here is a sample component that specifies a VerrazzanoHelidonWorkload.  To deploy an example application that demonstrates this workload type, see [Hello World Helidon]({{< relref "/docs/samples/hello-world.md" >}}).
```
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: hello-helidon-component
  namespace: hello-helidon
spec:
  workload:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoHelidonWorkload
    metadata:
      name: hello-helidon-workload
      labels:
        app: hello-helidon
    spec:
      deploymentTemplate:
        metadata:
          name: hello-helidon-deployment
        podSpec:
          containers:
            - name: hello-helidon-container
              image: "ghcr.io/verrazzano/example-helidon-greet-app-v1:0.1.10-3-20201016220428-56fb4d4"
              ports:
                - containerPort: 8080
                  name: http

```

#### VerrazzanoHelidonWorkload

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `oam.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | VerrazzanoHelidonWorkload |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `spec` |  [VerrazzanoHelidonWorkloadSpec](#verrazzanohelidonworkloadspec) | The desired state of a Verrazzano Helidon workload. |  Yes |


#### VerrazzanoHelidonWorkloadSpec
VerrazzanoHelidonWorkloadSpec specifies the desired state of a Verrazzano Helidon workload.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `deploymentTemplate` |  [DeploymentTemplate](#deploymenttemplate) | The embedded deployment. |  Yes |


#### DeploymentTemplate
DeploymentTemplate specifies the metadata and pod spec of the underlying deployment.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `strategy` | [DeploymentStrategy](https://kubernetes.io/docs/reference/generated/kubernetes-api/{{<kubernetes_api_version>}}/#deploymentstrategy-v1-apps) | The replacement strategy of the underlying deployment. | No |
| `podSpec` | [PodSpec](https://kubernetes.io/docs/reference/generated/kubernetes-api/{{<kubernetes_api_version>}}/#podspec-v1-core) | The pod spec of the underlying deployment. | Yes |


### VerrazzanoWebLogicWorkload
The VerrazzanoWebLogicWorkload custom resource contains the configuration information for a WebLogic [Domain](https://github.com/oracle/weblogic-kubernetes-operator/blob/main/documentation/domains/Domain.md) workload within Verrazzano.  Here is a sample component that specifies a VerrazzanoWebLogicWorkload.  To deploy an example application that demonstrates this workload type, see the ToDo List [Lift-and-Shift]({{< relref "/docs/guides/lift-and-shift/lift-and-shift.md" >}}) application.

```
apiVersion: core.oam.dev/v1alpha2
kind: Component
metadata:
  name: todo-domain
  namespace: todo-list
spec:
  workload:
    apiVersion: oam.verrazzano.io/v1alpha1
    kind: VerrazzanoWebLogicWorkload
    spec:
      template:
        metadata:
          name: todo-domain
          namespace: todo-list
        spec:
          domainUID: tododomain
          domainHome: /u01/domains/tododomain
          image: container-registry.oracle.com/verrazzano/example-todo:0.8.0
          imagePullSecrets:
            - name: tododomain-repo-credentials
          domainHomeSourceType: "FromModel"
          includeServerOutInPodLog: true
          replicas: 1
          webLogicCredentialsSecret:
            name: tododomain-weblogic-credentials
          configuration:
            introspectorJobActiveDeadlineSeconds: 900
            model:
              configMap: tododomain-jdbc-config
              domainType: WLS
              modelHome: /u01/wdt/models
              runtimeEncryptionSecret: tododomain-runtime-encrypt-secret
            secrets:
              - tododomain-jdbc-tododb
          serverPod:
            env:
              - name: JAVA_OPTIONS
                value: "-Dweblogic.StdoutDebugEnabled=false"
              - name: USER_MEM_ARGS
                value: "-Djava.security.egd=file:/dev/./urandom -Xms64m -Xmx256m "
              - name: WL_HOME
                value: /u01/oracle/wlserver
              - name: MW_HOME
                value: /u01/oracle
```

#### VerrazzanoWebLogicWorkload

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `apiVersion` | string | `oam.verrazzano.io/v1alpha1` | Yes |
| `kind` | string | VerrazzanoWebLogicWorkload |  Yes |
| `metadata` | ObjectMeta | Refer to Kubernetes API documentation for fields of metadata. |  No |
| `spec` |  [VerrazzanoWebLogicWorkloadSpec](#verrazzanoweblogicworkloadspec) | The desired state of a Verrazzano WebLogic workload. |  Yes |

#### VerrazzanoWebLogicWorkloadSpec
VerrazzanoWebLogicWorkloadSpec specifies the desired state of a Verrazzano WebLogic workload.

| Field | Type | Description | Required
| --- | --- | --- | --- |
| `template` |  [RawExtension](https://pkg.go.dev/k8s.io/apimachinery/pkg/runtime#RawExtension) | The metadata and spec for the underlying WebLogic [Domain](https://github.com/oracle/weblogic-kubernetes-operator/blob/main/documentation/domains/Domain.md) resource. |  Yes |
