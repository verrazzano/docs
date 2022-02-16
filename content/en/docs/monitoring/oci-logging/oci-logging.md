---
title: "OCI Logging Service"
linkTitle: OCI Logging Service
description: "Learn how to send Verrazzano logs to the OCI Logging service"
weight: 1
draft: false
---

The Oracle Cloud Infrastructure (OCI) Logging service is a highly scalable and fully managed single pane of glass for all the logs in your tenancy. You can configure Verrazzano to send logs to OCI Logging instead of OpenSearch.

## Set up custom logs
For a general overview, see [OCI Logging Overview](https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/loggingoverview.htm). 
Verrazzano can send its logs to OCI Custom Logs. You will need to provide two OCI Log identifiers in your Verrazzano
installation resource - one for Verrazzano system logs and one for application logs. Follow the [Custom Logs](https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/custom_logs.htm) 
documentation steps to create two custom logs. **Do not** create an agent configuration when creating a custom log,
otherwise the log records will be duplicated.

## Configuring Credentials
The Fluentd plug-in included with Verrazzano will use OCI instance principal authentication by default. You can
optionally configure Verrazzano with a user API signing key. API signing key authentication is required to send logs to
OCI Logging if the cluster is running outside of OCI.

{{< tabs tabTotal="2" tabID="1" tabName1="Instance Principal Credentials" tabName2="User API Credentials">}}
{{< tab tabNum="1" >}}
<br>

Create a dynamic group that includes the compute instances in your cluster's node pools and assign the appropriate policy,
so that the dynamic group is allowed to send log entries to the custom logs you created earlier. Pay close attention to
the [required permissions](https://docs.oracle.com/en-us/iaas/Content/Logging/Task/managinglogs.htm#required_permissions_logs_groups).

If the dynamic group and policy are configured incorrectly, then Fluentd will fail to send logs to OCI Logging.

<br/>

{{< /tab >}}
{{< tab tabNum="2" >}}
<br>

If you do not already have an API signing key, then see [Required Keys and OCIDS](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm)
in the OCI documentation. You need to create an OCI configuration file with the credential details and then use that
configuration file to create a secret. The following requirements must be satisfied for Fluentd OCI logging to work:
1. The profile name in the OCI configuration file must be `DEFAULT`
1. The `key_file` path in the OCI configuration file must `/root/.oci/key`. The actual key file does not need to be in
   that location, since you will be providing the actual key file location in a secret.
1. The user associated with the API key must have the appropriate OCI Identity and Access Management (IAM) policy
in place to allow the Fluentd plug-in to send logs to OCI. See [Details for Logging](https://docs.oracle.com/en-us/iaas/Content/Identity/Reference/loggingpolicyreference.htm)
in the OCI documentation for the IAM policies used by the OCI Logging service.

After the Verrazzano platform operator has been installed, create an opaque secret in the `verrazzano-install` namespace
from the OCI configuration and private key files. The key for the configuration file must be `config` and the key
for the private key file data must be `key`.

Here is an example `kubectl` command that will create the secret.

```
$ kubectl create secret generic oci-fluentd -n verrazzano-install \
      --from-file=config=/home/myuser/oci_config --from-file=key=/home/myuser/keys/oci_api.pem
```

The secret should look something like this.

```
apiVersion: v1
data:
  config: W0RFRkFVTFRdCnVzZXI9b2NpZDEudXN...
  key: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS...
kind: Secret
metadata:
  name: oci-fluentd
  namespace: verrazzano-install
type: Opaque
```

For convenience, there is a helper script available
[here]({{< release_source_url raw=true path="platform-operator/scripts/install/create_oci_fluentd_secret.sh" >}}) that
you can point at an existing OCI configuration file and it will create the secret for you. The script allows you to
override the default configuration file location, profile name, and the name of the secret.

After you have created the API secret, you need to configure the name of the secret in the Verrazzano custom resource,
under the OCI section of the Fluentd component settings. Extending the example custom resource from earlier,
your YAML file should look something like this.

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: vz-oci-logging
spec:
  profile: dev
  components:
    fluentd:
      enabled: true
      oci:
        systemLogId: ocid1.log.oc1.iad.system.example
        defaultAppLogId: ocid1.log.oc1.iad.app.example
        apiSecret: oci-fluentd
    elasticsearch:
      enabled: false
    kibana:
      enabled: false
```

The name of the secret must match the secret you created earlier.

{{< /tab >}}
{{< /tabs >}}

## Installing Verrazzano
OCI Logging is enabled in your cluster when installing Verrazzano. The Verrazzano installation custom resource has fields for specifying two custom logs: one for system logs and one for application logs. Here is an example Verrazzano installation YAML file.
Note that the API references Kibana, upcoming releases will use OpenSearch Dashboards in the public API.

```
apiVersion: install.verrazzano.io/v1alpha1
kind: Verrazzano
metadata:
  name: vz-oci-logging
spec:
  profile: dev
  components:
    fluentd:
      enabled: true
      oci:
        systemLogId: ocid1.log.oc1.iad.system.example
        defaultAppLogId: ocid1.log.oc1.iad.app.example
    elasticsearch:
      enabled: false
    kibana:
      enabled: false
```

## Overriding the default log objects
You can override the OCI Log object on an individual namespace. To specify a log identifier on a namespace, add an annotation named `verrazzano.io/oci-log-id` to the namespace. The value of the annotation is the OCI Log object identifier.

Here is an example namespace.
```
apiVersion: v1
kind: Namespace
metadata:
  annotations:
    verrazzano.io/oci-log-id: ocid1.log.oc1.iad.ns.app.example
  creationTimestamp: "2022-01-14T15:09:19Z"
  labels:
    istio-injection: enabled
    verrazzano-managed: "true"
  name: example
spec:
  finalizers:
  - kubernetes
status:
  phase: Active
```

Note that if you add and subsequently remove the annotation then the logs will revert to the default OCI Log object specified in the Verrazzano custom resource.

## Searching logs
To search Verrazzano logs, you can use the OCI Console, OCI CLI, or OCI SDK.

For example, using the OCI CLI to search the system logs for records emitted by the `verrazzano-application-operator` container.
```
$ oci logging-search search-logs --search-query=\
     "search \"ocid1.compartment.oc1..example/ocid1.loggroup.oc1.iad.example/ocid1.log.oc1.iad.example\" | \
     where \"data\".\"kubernetes.container_name\" = 'verrazzano-application-operator' | sort by datetime desc" \
     --time-start 2021-12-07 --time-end 2021-12-17
```

Search for all application log records in the `springboot` namespace.
```
$ oci logging-search search-logs --search-query=\
     "search \"ocid1.compartment.oc1..example/ocid1.loggroup.oc1.iad.example/ocid1.log.oc1.iad.example\" | \
     where \"data\".\"kubernetes.namespace_name\" = 'springboot' | sort by datetime desc" \
     --time-start 2021-12-07 --time-end 2021-12-17
```

For more information on searching logs, see the [Logging Query Language Specification](https://docs.oracle.com/en-us/iaas/Content/Logging/Reference/query_language_specification.htm).

## Troubleshooting
If you are not able to view Verrazzano logs in OCI Logging, then check the Fluentd container logs in the cluster to see if there are errors.
```
$ kubectl logs -n verrazzano-system -l app=fluentd --tail=-1
```
If you see "not authorized" error messages, then there is likely a problem with the OCI Dynamic Group or IAM policy that is preventing the Fluentd plug-in from communicating with the OCI API.

To ensure the appropriate permissions are in place, review the OCI Logging [required permissions](https://docs.oracle.com/en-us/iaas/Content/Logging/Task/managinglogs.htm#required_permissions_logs_groups) documentation.
