---
title: "Deploy a Kubernetes Sidecar With Verrazzano"
linkTitle: "Deploy Custom Sidecars"
description: "A guide for deploying custom sidecars to Verrazzano workload components"
weight: 2
draft: false
---

You may want to add additional sidecars to Verrazzano workloads; you can use any image or sidecar container. This guide will serve as an introduction by showing you how to create a custom Fluentd sidecar for application logs.

Verrazzano creates and manages a Fluentd sidecar injection for each WebLogic pod. This allows application logs to interact with the cluster-wide Fluentd DaemonSet.
However, these resources are not currently configurable and additional containers are required to customize the Fluentd configuration file and the container image.
For more information on Fluentd sidecars and DaemonSet, see [Configure Fluentd for Log Collection]({{< relref "/docs/observability/logging/fluentd/_index.md" >}}).

The following instructions use the [ToDo List]({{< relref "/docs/examples/wls-coh/todo-list" >}}) example application to demonstrate how to attach and deploy a custom Fluentd sidecar to a [VerrazzanoWebLogicWorkload]({{< relref "/docs/reference/vao-oam-v1alpha1#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkload" >}}) component. Before deploying the application, you will need to edit the application and component YAML files.
Run the following commands to create a local copy of them:
```
$ curl {{< release_source_url raw=true path=examples/todo-list/todo-list-components.yaml >}} --output todo-list-components.yaml
$ curl {{< release_source_url raw=true path=examples/todo-list/todo-list-application.yaml >}} --output todo-list-application.yaml
```
The `todo-list-components.yaml` file contains the [VerrazzanoWebLogicWorkload]({{< relref "/docs/reference/vao-oam-v1alpha1#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkload" >}}), which is where you will modify the deployment.

## Create a Fluentd custom sidecar configuration file

Before deploying the [VerrazzanoWebLogicWorkload]({{< relref "/docs/reference/vao-oam-v1alpha1#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkload" >}}) component, create a [ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/) that contains the Fluentd config file.
{{< clipboard >}}
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
   name: fluentdconf
   namespace: todo-list
data:
   fluent.conf: |
      ...
      <match **>
        @type stdout
      </match>

```
{{< /clipboard >}}
To interact with the [Fluentd DaemonSet]({{< relref "/docs/observability/logging/fluentd/_index.md#fluentd-daemonset" >}}) that Verrazzano manages, the configuration must redirect logs to stdout, as shown in the match block at the end of the Fluentd configuration file.
This ConfigMap must be deployed before or with all other application resources.

## Create Fluentd custom sidecar volumes

Now that the Fluentd configuration ConfigMap is deployed, create volumes to grant Fluentd access to the application logs and the Fluentd configuration file.
{{< clipboard >}}
```yaml
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
          image: container-registry.oracle.com/verrazzano/example-todo:0.1.12-1-20210624160519-017d358
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
            # ---- BEGIN: Add volumes for Fluentd container ----
            volumes:
              - emptyDir: {}
                name: shared-log-files
              - name: fdconfig
                configMap:
                  name: fluentdconf
            # ---- END: Add volumes for Fluentd container  ----
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
{{< /clipboard >}}
The example volume `shared-log-files` is used to enable the Fluentd container to view logs from application containers. This example uses an `emptyDir` volume type for ease of access, but you can use other volume types.

The `fdconfig` example volume mounts the previously deployed ConfigMap containing the Fluentd configuration. This allows the attached Fluentd sidecar to access the embedded Fluentd configuration file.

## Create the Fluentd custom sidecar container

The final resource addition to the [VerrazzanoWebLogicWorkload]({{< relref "/docs/reference/vao-oam-v1alpha1#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkload" >}}) is to create the custom sidecar container.
{{< clipboard >}}
```yaml
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
          image: container-registry.oracle.com/verrazzano/example-todo:0.1.12-1-20210624160519-017d358
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
            # ---- BEGIN: Add Fluentd container with volumeMounts  ----
            containers:
              - image: ghcr.io/verrazzano/fluentd-kubernetes-daemonset:v1.12.3-20210517195222-f345ec2
                name: fluentd
                env:
                  - name: FLUENT_UID
                    value: root
                  - name: FLUENT_CONF
                    value: fluent.conf
                  - name: FLUENTD_ARGS
                    value: -c /fluentd/etc/fluent.conf
                volumeMounts:
                  - mountPath: /scratch
                    name: shared-log-files
                    readOnly: true
                  - name: fdconfig
                    mountPath: /fluentd/etc/
            # ---- END: Add Fluentd container with volumeMounts  ----
            volumes:
              - emptyDir: {}
                name: shared-log-files
              - name: fdconfig
                configMap:
                  name: fluentdconf
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
{{< /clipboard >}}

This example container uses the Verrazzano Fluentd image, but you can use any image with additional Fluentd plug-ins in its place.

Mounted are both volumes created to enable the Fluentd sidecar to monitor and parse logs.
[VerrazzanoWebLogicWorkloads]({{< relref "/docs/reference/vao-oam-v1alpha1#oam.verrazzano.io/v1alpha1.VerrazzanoWebLogicWorkload" >}}) mount a volume in the `/scratch` directory containing log files.
Thus, any sidecar containers are limited to log access under that directory. As shown previously, the `shared-log-file` volume is mounted at `/scratch` for this reason.

The example Fluentd configuration volume is mounted at `/fluentd/etc/`. While this path is more flexible, the `FLUEND_ARGS` environment variable needs to be updated accordingly.

## Deploy the Fluentd sidecar

Now that the resources have been configured, you can deploy the application. Follow Steps 1 through 3 in the [ToDo List]({{< relref "/docs/examples/wls-coh/todo-list" >}}) example application instructions.
Replace the deployment commands in Step 4 with your locally edited YAML files:
{{< clipboard >}}
<div class="highlight">

```
$ kubectl apply -f todo-list-components.yaml
$ kubectl apply -f todo-list-application.yaml
```

</div>
{{< /clipboard >}}

Now, follow the [ToDo List]({{< relref "/docs/examples/wls-coh/todo-list" >}}) instructions from Step 5 onward, as needed.

To verify that a deployment successfully created a custom Fluentd sidecar:
- Verify that the container name exists on the WebLogic application pod.
{{< clipboard >}}
<div class="highlight">

  ```
  $ kubectl get pods -n <application-namespace> <application-pod-name> -o jsonpath="{.spec.containers[*].name}" | tr -s '[[:space:]]' '\n'
  ...
  fluentd
  ...
  ```

</div>
{{< /clipboard >}}

- Verify that the Fluentd sidecar is redirecting logs to stdout.
{{< clipboard >}}
<div class="highlight">

  ```
  $ kubectl logs -n <application-namespace> <application-pod-name> fluentd
  ```

</div>
{{< /clipboard >}}

- Follow the instructions at [Verrazzano Logging]({{< relref "/docs/observability/logging" >}}) to ensure that the [Fluentd DaemonSet]({{< relref "/docs/observability/logging/fluentd/_index.md#fluentd-daemonset" >}}) collected the logs from stdout.
  These logs will appear in the Verrazzano-managed [OpenSearch]({{< relref "/docs/observability/logging/configure-opensearch" >}}) and [OpenSearch Dashboards]({{< relref "/docs/observability/logging/configure-opensearch#opensearch-dashboards" >}}).
