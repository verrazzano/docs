# Custom Fluentd Sidecar

Verrazzano creates and manages a Fluentd sidecar injection for each WebLogic pod.
However, these resources are static and additional containers are required to customize the Fluentd configuration file and the container image.

Outlined are instructions on attaching and deploying custom Fluentd sidecars to [VerrazzanoWebLogicWorkload]({{< relref "/docs/reference/API/OAM/Workloads#verrazzanoweblogicworkload" >}}) components.

## Fluentd Custom Sidecar Configuration File

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
In order to interact with the [Fluentd DaemonSet]({{< relref "/docs/monitoring/logs/#fluentd-daemonset" >}}) that Verrazzano manages, the configuration must redirect logs to stdout as shown in the match block at the end of the above Fluentd config file.

## Fluentd Custom Sidecar Volumes

Now that the Fluentd configuration ConfigMap is deployed, create volumes to grant Fluentd access to the application logs and the Fluentd configuration file.
```yaml
workload:
   apiVersion: oam.verrazzano.io/v1alpha1
   kind: VerrazzanoWebLogicWorkload
   ...
   spec:
      template:
         spec:
            serverPod:
               volumes:
                  - emptyDir: {}
                    name: shared-log-files
                  - name: fdconfig
                    configMap:
                       name: fluentdconf

```
The example volume `shared-log-files` is used to enable the Fluentd container to view logs from application containers. This example utilized an emptyDir volume type for ease of access, but other volume types can be used.

The `fdconfig` example volume mounts the previously deployed ConfigMap containing the Fluentd configuration. This allows the attached Fluentd sidecar to access the embedded Fluentd configuration file.

## Fluentd Custom Sidecar Container

The final resource addition to the [VerrazzanoWebLogicWorkload]({{< relref "/docs/reference/API/OAM/Workloads#verrazzanoweblogicworkload" >}}) is creating the additional sidecar container.

```yaml
workload:
   apiVersion: oam.verrazzano.io/v1alpha1
   kind: VerrazzanoWebLogicWorkload
   ...
   spec:
      template:
         spec:
            serverPod:
               containers:
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
                    - mountPath: /scratch
                      name: shared-log-files
                      readOnly: true
                    - name: fdconfig
                      mountPath: /fluentd/etc/

```

This example container uses the [default Fluentd image](https://hub.docker.com/r/fluent/fluentd/) published on Dockerhub, but any image with additional Fluentd plugins can be used in its place.

Mounted are both volumes created to enable the Fluentd sidecar to monitor and parse logs.
[VerrazzanoWebLogicWorkloads]({{< relref "/docs/reference/API/OAM/Workloads#verrazzanoweblogicworkload" >}}) mount a volume in the `/scratch` directory containing log files.
Thus, any sidecar containers are limited to log access under that directory. As shown above, the `shared-log-file` volume is mounted at `/scratch` for this reason.

The example Fluentd configuration volume is mounted at `/fluentd/etc/`. While this path is more flexible, alterations to the example container environment variables are required to support alternative paths.

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
