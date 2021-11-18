# ToDo List

ToDo List is an example application containing a WebLogic component.
For more information and the source code of this application, see the [Verrazzano Examples](https://github.com/verrazzano/examples).

## Before you begin

* Set up a multicluster Verrazzano environment following the [installation instructions]({{< relref "/docs/setup/install/multicluster/_index.md" >}}).
* The example assumes that there is a managed cluster named `managed1` associated with the multicluster environment.
If your environment does not have a cluster of that name, then you should edit the deployment files and change the cluster name
listed in the `placement` section.
* To download the example application image, you must first accept the license agreement.
  * In a browser, navigate to https://container-registry.oracle.com/ and sign in.
  * Search for `example-todo` and select the image name in the results.
  * Click Continue, then read and accept the license agreement.

Setup the following environment variables to point to the kubeconfig for the admin and managed clusters.

```
$ export KUBECONFIG_ADMIN=/path/to/your/adminclusterkubeconfig
$ export KUBECONFIG_MANAGED1=/path/to/your/managedclusterkubeconfig
```

**NOTE:** The ToDo List application deployment files are contained in the Verrazzano project located at
`<VERRAZZANO_HOME>/examples/multicluster/todo-list`, where `<VERRAZZANO_HOME>` is the root of the Verrazzano project.


## Deploy the ToDo List example application

1. Create a namespace for the multicluster ToDo List example by applying the Verrazzano project file.
   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/todo-list/verrazzano-project.yaml >}}
   ```

1. Create a `docker-registry` secret to enable pulling the ToDo List example image from the registry.
   ```
   $ kubectl create secret docker-registry tododomain-repo-credentials \
           --docker-server=container-registry.oracle.com \
           --docker-username=YOUR_REGISTRY_USERNAME \
           --docker-password=YOUR_REGISTRY_PASSWORD \
           --docker-email=YOUR_REGISTRY_EMAIL \
           -n mc-todo-list
   ```

   Replace `YOUR_REGISTRY_USERNAME`, `YOUR_REGISTRY_PASSWORD`, and `YOUR_REGISTRY_EMAIL`
   with the values you use to access the registry.

1. Create and label secrets for the WebLogic domain:
   ```
   # Replace the values of the WLS_USERNAME and WLS_PASSWORD environment variables as appropriate.
   $ export WLS_USERNAME=<username>
   $ export WLS_PASSWORD=<password>
   $ kubectl create secret generic tododomain-weblogic-credentials \
       --from-literal=password=$WLS_PASSWORD \
       --from-literal=username=$WLS_USERNAME \
       -n mc-todo-list

   $ kubectl create secret generic tododomain-jdbc-tododb \
       --from-literal=username=$WLS_USERNAME \
       --from-literal=password=$WLS_PASSWORD \
       -n mc-todo-list

   $ kubectl -n mc-todo-list label secret tododomain-jdbc-tododb weblogic.domainUID=tododomain
   ```

   Note that the ToDo List example application is preconfigured to use specific secret names.
   For the source code of this application, see the [Verrazzano Examples](https://github.com/verrazzano/examples).

1. Apply the component and multicluster application resources to deploy the ToDo List application.
   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/todo-list/todo-list-components.yaml >}}

   $ kubectl --kubeconfig $KUBECONFIG_ADMIN apply \
       -f {{< release_source_url raw=true path=examples/multicluster/todo-list/mc-todo-list-application.yaml >}}
   ```

1. Wait for the ToDo List example application to be ready.
   The `tododomain-adminserver` pod may take several minutes to be created and `Ready`.
   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 wait pod \
       --for=condition=Ready tododomain-adminserver \
       -n mc-todo-list \
       --timeout=300s
   ```

1. Get the generated host name for the application.
   ```
   $ HOST=$(kubectl --kubeconfig $KUBECONFIG_MANAGED1 get gateway \
         -n mc-todo-list \
         -o jsonpath='{.items[0].spec.servers[0].hosts[0]}')
   $ echo $HOST
   
   # Sample output
   todo-appconf.mc-todo-list.11.22.33.44.nip.io
   ```

1. Get the `EXTERNAL_IP` address of the `istio-ingressgateway` service.
   ```
   $ ADDRESS=$(kubectl --kubeconfig $KUBECONFIG_MANAGED1 get service \
        -n istio-system istio-ingressgateway \
        -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
   $ echo $ADDRESS
   
   # Sample output
   11.22.33.44
   ```   

1. Access the ToDo List example application:

   * **Using the command line**
     ```
     # The expected response of this query is the HTML of a web page
     $ curl -sk https://${HOST}/todo/ \
         --resolve ${HOST}:443:${ADDRESS}
     ```
     If you are using `nip.io`, then you do not need to include `--resolve`.
   * **Local testing with a browser**

     Temporarily, modify the `/etc/hosts` file (on Mac or Linux)
     or `c:\Windows\System32\Drivers\etc\hosts` file (on Windows 10),
     to add an entry mapping the host name to the ingress gateway's `EXTERNAL-IP` address.
     For example:
     ```
     11.22.33.44 todo.example.com
     ```
     Then, you can access the application in a browser at `https://todo.example.com/todo`.
   * **Using your own DNS name**
     * Point your own DNS name to the ingress gateway's `EXTERNAL-IP` address.
     * In this case, you would need to have edited the `todo-list-application.yaml` file
       to use the appropriate value under the `hosts` section (such as `yourhost.your.domain`),
       before deploying the ToDo List application.
     * Then, you can use a browser to access the application at `https://<yourhost.your.domain>/todo/`.

      Accessing the application in a browser will open a page, "Derek's ToDo List",
      with an edit field and an **Add** button that lets add tasks.

1. A variety of endpoints associated with
   the deployed ToDo List application, are available to further explore the logs, metrics, and such.
   Accessing them may require the following:

   * Run this command to get the password that was generated for the telemetry components:
     ```
     $ kubectl --kubeconfig $KUBECONFIG_ADMIN get secret \
         --namespace verrazzano-system verrazzano -o jsonpath={.data.password} | base64 \
         --decode; echo
     ```
     The associated user name is `verrazzano`.

   * You will have to accept the certificates associated with the endpoints.

   You can retrieve the list of available ingresses with following command:

   ```
   $ kubectl --kubeconfig $KUBECONFIG_ADMIN get ingress -n verrazzano-system
   
   # Sample output
   NAME                    CLASS    HOSTS                                                 ADDRESS       PORTS     AGE
   verrazzano-ingress      <none>   verrazzano.default.11.22.33.44.nip.io                 11.22.33.44   80, 443   7d
   vmi-system-es-ingest    <none>   elasticsearch.vmi.system.default.11.22.33.44.nip.io   11.22.33.44   80, 443   7d
   vmi-system-grafana      <none>   grafana.vmi.system.default.11.22.33.44.nip.io         11.22.33.44   80, 443   7d
   vmi-system-kiali        <none>   kiali.vmi.system.default.11.22.33.44.nip.io           11.22.33.44   80, 443   7d
   vmi-system-kibana       <none>   kibana.vmi.system.default.11.22.33.44.nip.io          11.22.33.44   80, 443   7d
   vmi-system-prometheus   <none>   prometheus.vmi.system.default.11.22.33.44.nip.io      11.22.33.44   80, 443   7d
   ```

   Using the ingress host information, some of the endpoints available are:

   | Description | Address | Credentials |
   | ----------- | ------- | ----------- |
   | Kibana      | `https://[vmi-system-kibana ingress host]`     | `verrazzano`/`telemetry-password` |
   | Grafana     | `https://[vmi-system-grafana ingress host]`    | `verrazzano`/`telemetry-password` |
   | Prometheus  | `https://[vmi-system-prometheus ingress host]` | `verrazzano`/`telemetry-password` |
   | Kiali | `https://[vmi-system-kiali ingress host]` | `verrazzano`/`telemetry-password` |    

## Troubleshooting

1. Verify that the application configuration, domain, and ingress trait all exist.
   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get ApplicationConfiguration -n mc-todo-list
   
   # Sample output
   NAME           AGE
   todo-appconf   19h

   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get Domain -n mc-todo-list
   
   # Sample output
   NAME          AGE
   todo-domain   19h

   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get IngressTrait -n mc-todo-list
   
   # Sample output
   NAME                           AGE
   todo-domain-trait-7cbd798c96   19h
   ```

1. Verify that the WebLogic Administration Server and MySQL pods have been created and are running.
   Note that this will take several minutes.
   ```
   $ kubectl --kubeconfig $KUBECONFIG_MANAGED1 get pods -n mc-todo-list

   # Sample output
   NAME                     READY   STATUS    RESTARTS   AGE
   mysql-5c75c8b7f-vlhck    2/2     Running   0          19h
   tododomain-adminserver   4/4     Running   0          19h
   ```

## Undeploy the ToDo List application

Regardless of its location, to undeploy the application,
delete the application resources and the project from the admin cluster.
Undeploy affects all clusters in which the application is located.

```shell
# Delete the multicluster application configuration
$ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
    -f {{< release_source_url raw=true path=examples/multicluster/todo-list/mc-todo-list-application.yaml >}}
# Delete the components for the application
$ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
    -f {{< release_source_url raw=true path=examples/multicluster/todo-list/todo-list-components.yaml >}}
# Delete the project
$ kubectl --kubeconfig $KUBECONFIG_ADMIN delete \
    -f {{< release_source_url raw=true path=examples/multicluster/todo-list/verrazzano-project.yaml >}}
# Delete the namespace created on the admin and managed clusters
$ kubectl --kubeconfig $KUBECONFIG_ADMIN delete namespace mc-todo-list
$ kubectl --kubeconfig $KUBECONFIG_MANAGED1 delete namespace mc-todo-list
```
