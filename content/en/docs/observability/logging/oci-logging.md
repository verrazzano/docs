---
title: "Oracle Cloud Infrastructure Logging Service"
weight: 4
draft: false
aliases:
  - /docs/monitoring/oci-logging/oci-logging
---

The Oracle Cloud Infrastructure Logging service is a highly scalable and fully managed single view for
all the logs in your tenancy. You can configure Verrazzano to send logs to Oracle Cloud Infrastructure Logging instead of OpenSearch.
For general information, see Oracle Cloud Infrastructure [Logging Overview](https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/loggingoverview.htm).

## Set up custom logs
Verrazzano can send its logs to Oracle Cloud Infrastructure custom logs. You will need to provide two Oracle Cloud Infrastructure Log identifiers in your Verrazzano
installation resource: one for Verrazzano system logs and one for application logs. Follow the steps in
[Creating Custom Logs](https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/custom_logs.htm) to create two
custom logs. **Do not** create an agent configuration when creating a custom log, otherwise the log records will be duplicated.

## Configure credentials
The Fluentd plug-in included with Verrazzano will use Oracle Cloud Infrastructure instance principal authentication by default. Optionally, you
can configure Verrazzano with a user API signing key. API signing key authentication is required to send logs to
Oracle Cloud Infrastructure Logging if the cluster is running outside of Oracle Cloud Infrastructure.

- [Instance principal authentication](#instance-principal-authentication)
- [User API signing key](#user-api-signing-key)

### Instance principal authentication

Create a dynamic group that includes the compute instances in your cluster's node pools and assign the appropriate policy,
so that the dynamic group is allowed to send log entries to the custom logs you created earlier. Pay close attention to
the [required permissions](https://docs.oracle.com/en-us/iaas/Content/Logging/Task/managinglogs.htm#required_permissions_logs_groups).

If the dynamic group and policy are configured incorrectly, then Fluentd will fail to send logs to Oracle Cloud Infrastructure Logging.

### User API signing key

If you do not already have an API signing key, then see [Required Keys and OCIDs](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm)
in the Oracle Cloud Infrastructure documentation. You need to create an Oracle Cloud Infrastructure configuration file with the credential details and then use that
configuration file to create a secret.

The following requirements must be met for Fluentd Oracle Cloud Infrastructure Logging to work:
1. The profile name in the Oracle Cloud Infrastructure configuration file must be `DEFAULT`.
1. The `key_file` path in the Oracle Cloud Infrastructure configuration file must be `/root/.oci/key`. The actual key file does not need to be in
   that location, because you will be providing the actual key file location in a secret.
1. The user associated with the API key must have the appropriate Oracle Cloud Infrastructure Identity and Access Management (IAM) policy
in place to allow the Fluentd plug-in to send logs to Oracle Cloud Infrastructure. See [Details for Logging](https://docs.oracle.com/en-us/iaas/Content/Identity/Reference/loggingpolicyreference.htm)
in the Oracle Cloud Infrastructure documentation for the IAM policies used by the Oracle Cloud Infrastructure Logging service.

After the Verrazzano platform operator has been installed, create an opaque secret in the `verrazzano-install` namespace
from the Oracle Cloud Infrastructure configuration and private key files. The key for the configuration file must be `config` and the key
for the private key file data must be `key`.

Here is an example `kubectl` command that will create the secret.
{{< clipboard >}}
<div class="highlight">

```
$ kubectl create secret generic oci-fluentd -n verrazzano-install \
      --from-file=config=/home/myuser/oci_config --from-file=key=/home/myuser/keys/oci_api.pem
```

</div>
{{< /clipboard >}}

The secret should look something like this.

{{< clipboard >}}
<div class="highlight">

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

</div>
{{< /clipboard >}}


For convenience, there is a helper script available
[here]({{< release_source_url raw=true path="platform-operator/scripts/install/create_oci_fluentd_secret.sh" >}}) that
you can point at an existing Oracle Cloud Infrastructure configuration file and it will create the secret for you. The script allows you to
override the default configuration file location, profile name, and the name of the secret.


## Specify custom logs
Oracle Cloud Infrastructure Logging is enabled in your cluster when installing Verrazzano. The Verrazzano installation custom resource has fields for specifying two custom logs: one for system logs and one for application logs. Here is an example Verrazzano
installation YAML file for each type of credential.
- [Instance principal credentials](#instance-principal-credentials)
- [User API credentials](#user-api-credentials)

### Instance principal credentials
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
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
    opensearch:
      enabled: false
    opensearchDashboards:
      enabled: false
```

</div>
{{< /clipboard >}}

### User API credentials

When using user API credentials, you need to configure the name of the secret in the Verrazzano custom resource,
under the Oracle Cloud Infrastructure section of the Fluentd component settings. Your YAML file should look something like this.
{{< clipboard >}}
<div class="highlight">

```
apiVersion: install.verrazzano.io/v1beta1
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
    opensearch:
      enabled: false
    opensearchDashboards:
      enabled: false
```

</div>
{{< /clipboard >}}

The `apiSecret` value must match the secret you created earlier when configuring the user API credentials.


## Override the default log objects
You can override the Oracle Cloud Infrastructure Log object on an individual namespace. To specify a log identifier on a namespace, add an annotation named `verrazzano.io/oci-log-id` to the namespace. The value of the annotation is the Oracle Cloud Infrastructure Log object identifier.

Here is an example namespace.
{{< clipboard >}}
<div class="highlight">

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

</div>
{{< /clipboard >}}

Note that if you add and subsequently remove the annotation, then the logs will revert to the default Oracle Cloud Infrastructure Log object
specified in the Verrazzano custom resource.
