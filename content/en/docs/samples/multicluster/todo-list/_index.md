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

**NOTE:** The ToDo List application deployment files are contained in the Verrazzano project located at
`<VERRAZZANO_HOME>/examples/todo-list`, where `<VERRAZZANO_HOME>` is the root of the Verrazzano project.


## Deploy the ToDo List example application

1. Create a namespace for the multicluster ToDo List example by applying the Verrazzano project file.
   ```
   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl apply \
       -f {{< release_source_url raw=true path=examples/multicluster/todo-list/verrazzano-project.yaml >}}
   ```

1. Download the `mc-docker-registry-secret.yaml` file.
   ```
   $ wget  https://raw.githubusercontent.com/verrazzano/verrazzano/v1.0.0/examples/multicluster/todo-list/mc-docker-registry-secret.yaml
   ```

1. Edit the `mc-docker-registry-secret.yaml` file and replace the
`<BASE 64 ENCODED DOCKER CONFIG JSON>` with the value generated from the following command.
   ```
   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl create secret docker-registry temp \
       --dry-run=client \
       --docker-server=container-registry.oracle.com \
       --docker-username=YOUR_REGISTRY_USERNAME \
       --docker-password=YOUR_REGISTRY_PASSWORD \
       --docker-email=YOUR_REGISTRY_EMAIL \
       -o jsonpath='{.data.\.dockerconfigjson}'
   ```
   Replace `YOUR_REGISTRY_USERNAME`, `YOUR_REGISTRY_PASSWORD`, and `YOUR_REGISTRY_EMAIL`
   with the values you use to access the registry. 
      
1. Apply the `mc-docker-registry-secret.yaml` file to create the multicluster secret.  The multicluster secret 
resource will generate the required secret in the mc-todo-list namespace.
   ```
   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl apply -f mc-docker-registry-secret.yaml
   ```

1. Download the `mc-weblogic-domain-secret.yaml` and `mc-tododb-secret.yaml` files.
   ```
   $ wget https://raw.githubusercontent.com/verrazzano/verrazzano/v1.0.0/examples/multicluster/todo-list/mc-weblogic-domain-secret.yaml
   $ wget https://raw.githubusercontent.com/verrazzano/verrazzano/v1.0.0/examples/multicluster/todo-list/mc-tododb-secret.yaml
   ```

1. Edit the `mc-weblogic-domain-secret.yaml` and `mc-tododb-secret.yaml` files,
replacing the `THE_USERNAME` and `THE_PASSWORD` values with the respective WebLogic username and password.
   ```
      username: THE_USERNAME
      password: THE_PASSWORD
   ```
      
1. Apply the `mc-weblogic-domain-secret.yaml` and `mc-tododb-secret.yaml` files.  The 
multicluster secret resource will generate the required secret in the mc-todo-list namespace.
   ```
   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl apply -f mc-weblogic-domain-secret.yaml
   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl apply -f mc-tododb-secret.yaml
   ```

1. Apply the application and component resources to deploy the ToDo List application.
   ```
   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl apply \
       -f {{< release_source_url raw=true path=examples/multicluster/todo-list/todo-list-components.yaml >}}

   $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl apply \
       -f {{< release_source_url raw=true path=examples/multicluster/todo-list/todo-list-application.yaml >}}
   ```

1. Wait for the ToDo List example application to be ready.  This 
   The `tododomain-adminserver` pod may take several minutes to be created and `Ready`.
   ```
   $ KUBECONFIG=$KUBECONFIG_MANAGED1 kubectl wait pod \
       --for=condition=Ready tododomain-adminserver \
       -n mc-todo-list
   ```

1. Get the generated host name for the application.
   ```
   $ HOST=$(KUBECONFIG=$KUBECONFIG_MANAGED1 kubectl get gateway \
         -n mc-todo-list \
         -o jsonpath={.items[0].spec.servers[0].hosts[0]})
   $ echo $HOST
   todo-appconf.mc-todo-list.11.22.33.44.nip.io
   ```

1. Get the `EXTERNAL_IP` address of the `istio-ingressgateway` service.
   ```
   $ ADDRESS=$(KUBECONFIG=$KUBECONFIG_MANAGED1 kubectl get service \
        -n istio-system istio-ingressgateway \
        -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
   $ echo $ADDRESS
   11.22.33.44
   ```   

1. Access the ToDo List example application:

   * **Using the command line**
     ```
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
     $ KUBECONFIG=$KUBECONFIG_ADMIN kubectl get secret \
         --namespace verrazzano-system verrazzano -o jsonpath={.data.password} | base64 \
         --decode; echo
     ```
     The associated user name is `verrazzano`.

   * You will have to accept the certificates associated with the endpoints.

   You can retrieve the list of available ingresses with following command:

   ```
   $ KUBECONFIG=$KUBECONFIG_MANAGED1 kubectl get ingress -n verrazzano-system
   NAME                         CLASS    HOSTS                                                     ADDRESS           PORTS     AGE
   verrazzano-ingress           <none>   verrazzano.default.140.141.142.143.nip.io                 140.141.142.143   80, 443   7d2h
   vmi-system-es-ingest         <none>   elasticsearch.vmi.system.default.140.141.142.143.nip.io   140.141.142.143   80, 443   7d2h
   vmi-system-grafana           <none>   grafana.vmi.system.default.140.141.142.143.nip.io         140.141.142.143   80, 443   7d2h
   vmi-system-kibana            <none>   kibana.vmi.system.default.140.141.142.143.nip.io          140.141.142.143   80, 443   7d2h
   vmi-system-prometheus        <none>   prometheus.vmi.system.default.140.141.142.143.nip.io      140.141.142.143   80, 443   7d2h
   ```

   Using the ingress host information, some of the endpoints available are:

   | Description | Address | Credentials |
   | ----------- | ------- | ----------- |
   | Kibana      | `https://[vmi-system-kibana ingress host]`     | `verrazzano`/`telemetry-password` |
   | Grafana     | `https://[vmi-system-grafana ingress host]`    | `verrazzano`/`telemetry-password` |
   | Prometheus  | `https://[vmi-system-prometheus ingress host]` | `verrazzano`/`telemetry-password` |

## Troubleshooting

1. Verify that the application configuration, domain, and ingress trait all exist.
   ```
   $ KUBECONFIG=$KUBECONFIG_MANAGED1 kubectl get ApplicationConfiguration -n mc-todo-list
   NAME           AGE
   todo-appconf   19h

   $ KUBECONFIG=$KUBECONFIG_MANAGED1 kubectl get Domain -n mc-todo-list
   NAME          AGE
   todo-domain   19h

   $ KUBECONFIG=$KUBECONFIG_MANAGED1 kubectl get IngressTrait -n mc-todo-list
   NAME                           AGE
   todo-domain-trait-7cbd798c96   19h
   ```

1. Verify that the WebLogic Administration Server and MySQL pods have been created and are running.
   Note that this will take several minutes.
   ```
   $ KUBECONFIG=$KUBECONFIG_MANAGED1 kubectl get pods -n mc-todo-list

   NAME                     READY   STATUS    RESTARTS   AGE
   mysql-5c75c8b7f-vlhck    1/1     Running   0          19h
   tododomain-adminserver   2/2     Running   0          19h
   ```
