# Custom Fluentd Sidecar

In order to add flexibility and customization to logging with Verrazzano, additional components must be created to interact with the Verrazzano logging DaemonSet.
Verrazzano currently manages Fluentd sidecars as a means to collect and funnel logs to the [Fluentd DaemonSet]({{< relref "/docs/monitoring/logs/#fluentd-daemonset" >}}).
However, these sidecars are not currently customizable. 
If users want to utilize alternative Fluentd configurations or images, users can create their own sidecar to interact with the DaemonSet. 
Outlined below are steps necessary to create and deploy a Fluentd sidecar that interacts with the Verrazzano Fluentd DaemonSet

## Fluentd Custom Sidecar Configuration File

Before creating a [Deployment](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/) with application details, create a [ConfigMap](https://kubernetes.io/docs/concepts/configuration/configmap/) that contains the Fluentd config file.
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
In order to interact with the [Fluentd DaemonSet]({{< relref "/docs/monitoring/logs/#fluentd-daemonset" >}}) that Verrazzano manages, the configuration must redirect logs to stdout as shown in the match block at the end of the above Fluentd config file.

## Fluentd Custom Sidecar Volumes

Now that the Fluentd configuration ConfigMap is deployed, create volumes to grant Fluentd access to the application logs and the Fluentd configuration file.
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
The example volume `shared-log-files` is used to enable the Fluentd container to view logs from application containers. This example utilized an emptyDir volume type for ease of access, but other volume types can be used.

The `fdconfig` example volume mounts the previously deployed ConfigMap containing the Fluentd configuration. This allows the attached Fluentd sidecar to access the embedded Fluentd configuration file.

## Fluentd Custom Sidecar Container

The final resource addition to the Deployment is creating the additional sidecar container.

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
               
         - image: fluent/fluentd
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

This example container uses the [default Fluentd image](https://hub.docker.com/r/fluent/fluentd/) published on Dockerhub, but any image with additional Fluentd plugins can be used in its place.

Mounted are both volumes created to enable the Fluentd sidecar to monitor and parse logs.
The volume `shared-log-files` should be mounted at the location that the application writes log files.
The volumeMount for the application and sidecar should point to the same directory. 
This enables both containers to access log files within that directory.

The example Fluentd configuration volume is mounted at `/fluentd/etc/`. 
While this path is flexible, alterations to the example container environment variables are required to support alternative paths.

## Verifying Fluentd Sidecar Deployment

To verify that a deployment successfully created a custom Fluentd sidecar, the following steps can be taken.
- Verify that The container name exists on the WebLogic application pod.
    - ```
        $ kubectl get pods -n <application-namespace> <application-pod-name> -o jsonpath="{.spec.containers[*].name}" | tr -s '[[:space:]]' '\n'
        ...
        fluentd
        ...
        ```
- Verify that the Fluentd sidecar is redirecting logs to stdout.
    - ```
        kubectl logs -n <application-namespace> <application-pod-name> fluentd
        ```
- Follow the instructions on [Verrazzano Logging]({{< relref "/docs/monitoring/logs" >}}) to ensure the [Fluentd DaemonSet]({{< relref "/docs/monitoring/logs/#fluentd-daemonset" >}}) collected the logs from stdout.
  These logs should appear in the Verrazzano managed [ElasticSearch]({{< relref "/docs/monitoring/logs#elasticsearch" >}}) and [Kibana]({{< relref "/docs/monitoring/logs#kibana" >}})
