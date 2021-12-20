---
title: "OCI Logging Service"
linkTitle: OCI Logging Service
description: "Learn how to send Verrazzano logs to the OCI Logging service"
weight: 1
draft: false
---

The Oracle Cloud Infrastructure (OCI) Logging service is a highly scalable and fully managed single pane of glass for all the logs in your tenancy. You can configure Verrazzano to send logs to OCI Logging instead of Elasticsearch.

## Set up custom logs
For a general overview, see [OCI Logging Overview](https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/loggingoverview.htm). Verrazzano sends its logs to OCI Custom Logs. You will need to provide two OCI Log identifiers in your Verrazzano installation resource. Follow the [Custom Logs](https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/custom_logs.htm) documentation steps to create two custom logs. **Do not** create an agent configuration when creating a custom log, otherwise the log records will be duplicated.

Pay close attention to the [required permissions](https://docs.oracle.com/en-us/iaas/Content/Logging/Task/managinglogs.htm#required_permissions_logs_groups). If you do not define a dynamic group for your cluster and assign the appropriate policy, then Fluentd will fail to send logs to OCI Logging.

## Installing Verrazzano
OCI Logging is enabled in your cluster when installing Verrazzano. The Verrazzano installation custom resource has fields for specifying two custom logs: one for system logs and one for application logs. Here is an example Verrazzano installation YAML file.
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
      extraVolumeMounts:
        - source: /u01/data
      oci:
        systemLogId: ocid1.log.oc1.iad.system.example
        defaultAppLogId: ocid1.log.oc1.iad.app.example
    elasticsearch:
      enabled: false
    kibana:
      enabled: false
```

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
If you see "not authorized" error messages, then there is likely a problem with the OCI Dynamic Group or IAM policy that is preventing the Fluentd plugin from communicating with the OCI API.

To ensure the appropriate permissions are in place, review the OCI Logging [required permissions](https://docs.oracle.com/en-us/iaas/Content/Logging/Task/managinglogs.htm#required_permissions_logs_groups) documentation.
