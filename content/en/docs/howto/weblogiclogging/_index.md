---
title: "Customize Application Logging for WebLogic Workloads"
description: "A guide for deploying custom Fluentd sidecars to VerrazzanoWebLogicWorkload components"
weight: 4
draft: false
---

Verrazzano creates and manages a Fluentd sidecar injection for each WebLogic pod. This allows application logs to 
However, these resources are not currently configurable and additional containers are required to customize the Fluentd configuration file and the container image.
For more on how Verrazzano handles logging, read the [Logging](http://localhost:1313/docs/monitoring/logs/) documentation.

The following instructions show you how to attach and deploy custom Fluentd sidecars to [VerrazzanoWebLogicWorkloads]({{< relref "/docs/reference/API/OAM/Workloads#verrazzanoweblogicworkload" >}}) components.
The example YAML files in this document will be modeled after the [ToDo List]({{< relref "/docs/samples/todo-list" >}}) YAML files for context.

If you are new to [Open Application Model](https://oam.dev/) resources in Verrazzano, consult the [Applications](http://localhost:1313/docs/applications/) documentation before completing this configuration.

## Example Application

If you would like to test the following configuration on an example application, the Verrazzano [ToDo List]({{< relref "/docs/samples/todo-list" >}}) example application is a great place to start.
Before you deploy the application, you need to edit the application and component YAML files.
You can run the following commands to create a local copy of the application YAML files.
```
$ curl https://raw.githubusercontent.com/verrazzano/verrazzano/v1.0.0/examples/todo-list/todo-list-components.yaml --output todo-list-components.yaml
$ curl https://raw.githubusercontent.com/verrazzano/verrazzano/v1.0.0/examples/todo-list/todo-list-application.yaml --output todo-list-application.yaml
```
The `todo-list-components.yaml` contains the [VerrazzanoWebLogicWorkload]({{< relref "/docs/reference/API/OAM/Workloads#verrazzanoweblogicworkload" >}}) that is the focus of the following alterations.
This file is also a great place to store any complementary kubernetes resources that are deployed with the application.

With the local application yaml files downloaded, first follow the following instructions and later the [ToDo List]({{< relref "/docs/samples/todo-list" >}}) instructions to deploy this example application with a custom Fluentd sidecar.
Detailed information about the example application deployment is located in the [Deployment]({{< ref "#deploy-the-fluentd-sidecar" >}}) section of this document.

## Create a Fluentd custom sidecar configuration file

Before deploying a [VerrazzanoWebLogicWorkload]({{< relref "/docs/reference/API/OAM/Workloads#verrazzanoweblogicworkload" >}}) component, create a [ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/) that contains the Fluentd config file.
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
In order to interact with the [Fluentd DaemonSet]({{< relref "/docs/monitoring/logs/#fluentd-daemonset" >}}) that Verrazzano manages, the configuration must redirect logs to stdout, as shown in the match block at the end of the previous Fluentd config file.
This ConfigMap must be deployed before or with all other application resources.

## Create Fluentd custom sidecar volumes

Now that the Fluentd configuration ConfigMap is deployed, create volumes to grant Fluentd access to the application logs and the Fluentd configuration file.
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
            # ---- Add volumes for Fluentd container ----
            volumes:
              - emptyDir: {}
                name: shared-log-files
              - name: fdconfig
                configMap:
                  name: fluentdconf
            # ---- Add volumes for Fluentd container  ----
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
The example volume `shared-log-files` is used to enable the Fluentd container to view logs from application containers. This example uses an `emptyDir` volume type for ease of access, but you can use other volume types.

The `fdconfig` example volume mounts the previously deployed ConfigMap containing the Fluentd configuration. This allows the attached Fluentd sidecar to access the embedded Fluentd configuration file.

## Create the Fluentd custom sidecar container

The final resource addition to the [VerrazzanoWebLogicWorkload]({{< relref "/docs/reference/API/OAM/Workloads#verrazzanoweblogicworkload" >}}) is to create the custom sidecar container.

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
            # ---- Add Fluentd container with volumeMounts  ----
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
            # ---- Add Fluentd container with volumeMounts  ----
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

This example container uses the Verrazzano Fluentd image, but you can use any image with additional Fluentd plug-ins in its place.

Mounted are both volumes created to enable the Fluentd sidecar to monitor and parse logs.
[VerrazzanoWebLogicWorkloads]({{< relref "/docs/reference/API/OAM/Workloads#verrazzanoweblogicworkload" >}}) mount a volume in the `/scratch` directory containing log files.
Thus, any sidecar containers are limited to log access under that directory. As shown previously, the `shared-log-file` volume is mounted at `/scratch` for this reason.

The example Fluentd configuration volume is mounted at `/fluentd/etc/`. While this path is more flexible, alterations to the example container environment variables are required to support alternative paths.

## Deploy the Fluentd sidecar

Now that the resources have been configured, it is time to deploy the application.

If you used the example application, make sure to follow steps 1-3 in the [ToDo List]({{< relref "/docs/samples/todo-list" >}}) instructions before deploying the application.
The step 4 deployment commands should be replaced with your locally edited YAML files:
```
$ kubectl apply -f todo-list-components.yaml
$ kubectl apply -f todo-list-application.yaml
```
Now you are able to complete the [ToDo List]({{< relref "/docs/samples/todo-list" >}}) instructions from step 5 onward.

To verify that a deployment successfully created a custom Fluentd sidecar:
- Verify that the container name exists on the WebLogic application pod.
  ```
  $ kubectl get pods -n <application-namespace> <application-pod-name> -o jsonpath="{.spec.containers[*].name}" | tr -s '[[:space:]]' '\n'
  ...
  fluentd
  ...
  ```
- Verify that the Fluentd sidecar is redirecting logs to stdout.
  ```
  kubectl logs -n <application-namespace> <application-pod-name> fluentd
  ```
- Follow the instructions at [Verrazzano Logging]({{< relref "/docs/monitoring/logs" >}}) to ensure that the [Fluentd DaemonSet]({{< relref "/docs/monitoring/logs/#fluentd-daemonset" >}}) collected the logs from stdout.
  These logs will appear in the Verrazzano managed [ElasticSearch]({{< relref "/docs/monitoring/logs#elasticsearch" >}}) and [Kibana]({{< relref "/docs/monitoring/logs#kibana" >}}).
