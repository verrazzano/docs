---
title: "Customize Application Logging for Generic Workloads"
description: "A guide for deploying custom Fluentd sidecars"
weight: 3
draft: false
---

In order to add flexibility and customization to logging with Verrazzano, you must create additional components to interact with the Verrazzano logging DaemonSet.
Verrazzano currently manages Fluentd sidecars to collect and funnel logs to the [Fluentd DaemonSet]({{< relref "/docs/monitoring/logs/#fluentd-daemonset" >}}).
However, these sidecars are not currently configurable. 
If you want to use alternative Fluentd configurations or images, you can create a custom sidecar to interact with the DaemonSet.
The following steps show you how to create and deploy a custom Fluentd sidecar that interacts with the Verrazzano Fluentd DaemonSet.

## Create a Fluentd custom sidecar configuration file

Before creating a [Deployment](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/) with application details, create a [ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/) that contains the Fluentd config file.
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
   name: fluentdconf
   namespace: <application-namespace>
data:
   fluent.conf: |
      ...
      <match **>
        @type stdout
      </match>

```
In order to interact with the [Fluentd DaemonSet]({{< relref "/docs/monitoring/logs/#fluentd-daemonset" >}}) that Verrazzano manages, the configuration must redirect logs to stdout, as shown in the match block at the end of the previous Fluentd config file.
This ConfigMap must be deployed before or with the application resources.

## Create Fluentd custom sidecar volumes

After the Fluentd configuration ConfigMap is deployed, create volumes to grant Fluentd access to the application logs and the Fluentd configuration file.
```yaml
workload:
  apiVersion: apps/v1
  kind: Deployment
   ...
  spec:
    template:
      spec:
        volumes:
          - name: shared-log-files
            emptyDir: {}
          - name: fdconfig
            configMap:
              name: fluentdconf

```
The example volume `shared-log-files` lets the Fluentd container view logs from application containers. This example uses an `emptyDir` volume type for ease of access, but you can use other volume types.

The `fdconfig` example volume mounts the previously deployed ConfigMap containing the Fluentd configuration. This allows the attached Fluentd sidecar to access the embedded Fluentd configuration file.

## Create the Fluentd custom sidecar container

The final resource addition to the Deployment is to create the custom sidecar container.

```yaml
workload:
   apiVersion: apps/v1
   kind: Deployment
   ...
   spec:
     template:
       spec:
         containers:
         - name: user-application
           ...
           volumeMounts:
             - mountPath: /log/file/path
               name: shared-log-files
               
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
              - mountPath: /log/file/path
                name: shared-log-files
                readOnly: true
              - name: fdconfig
                mountPath: /fluentd/etc/

```

This example container uses the Verrazzano Fluentd image, but you can use any image with additional Fluentd plug-ins in its place.

Mounted are both volumes created to enable the Fluentd sidecar to monitor and parse logs.
The volume `shared-log-files` should be mounted at the location that the application writes log files.
The `volumeMount` for the application and sidecar should point to the same directory. 
This enables both containers to access log files within that directory.

The example Fluentd configuration volume is mounted at `/fluentd/etc/`. 
While this path is flexible, alterations to the example container environment variables are required to support alternative paths.

## Deploy the Fluentd sidecar

Now that you hae configured the resources, go ahead and deploy the application.

To verify that a deployment successfully created a custom Fluentd sidecar:
- Verify that the container name exists on the application pod.
  ```
  $ kubectl get pods -n <application-namespace> <application-pod-name> -o jsonpath="{.spec.containers[*].name}" | tr -s '[[:space:]]' '\n'
  ...
  fluentd
  ...
  ```
- Verify that the Fluentd sidecar is redirecting logs to stdout.
  ```
  $ kubectl logs -n <application-namespace> <application-pod-name> fluentd
  ```
- Follow the instructions at [Verrazzano Logging]({{< relref "/docs/monitoring/logs" >}}) to ensure that the [Fluentd DaemonSet]({{< relref "/docs/monitoring/logs/#fluentd-daemonset" >}}) collected the logs from stdout.
  These logs will appear in the Verrazzano managed [ElasticSearch]({{< relref "/docs/monitoring/logs#elasticsearch" >}}) and [Kibana]({{< relref "/docs/monitoring/logs#kibana" >}}).
