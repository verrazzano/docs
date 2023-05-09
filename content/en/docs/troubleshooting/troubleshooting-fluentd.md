---
title: "Fluentd"
linkTitle: "Fluentd"
description: "Troubleshoot a Fluentd permission issue when SELinux is in `enforcing` mode"
weight: 3
draft: false
---


**Issue**: Fluentd's inability to push logs to OpenSearch due to a permission issue when SELinux is in `enforcing` mode.

If you are unable to see logs in OpenSearch, it may be due to a permission issue in Fluentd when SELinux is in `enforcing` mode, which prevents Fluentd from pushing the logs to OpenSearch.

To troubleshoot the Fluentd permission issue, follow these steps:

1. Check Fluentd pod logs.
    - Identify the Fluentd pod related to the Verrazzano installation.
    - View the logs of the Fluentd pod using the following command:
{{< clipboard >}}
```sh
$ kubectl logs <fluentd-pod-name> -n verrazzano-system
```
{{< /clipboard >}}

2. Check for an error description.
    - Look for an error message in the Fluentd pod logs.
    - If you see an error with the following description, then follow the instructions in Step 3. Resolve permission issue.
   ```
   unexpected error error_class=Errno::EACCES error="Permission denied @ rb_sysopen - /var/log/vz-fluentd-containers.log.pos", it indicates a permission issue. Fluentd doesn't have enough privilege to write `.pos` file.
   ```
3. Resolve permission issue.
    - The issue occurs when SELinux is in `enforcing` mode on the worker nodes and Fluentd does not have the appropriate SELinux context to have read/write access to the logs directory.
    - Check if SELinux is in `enforcing` mode by running this command on the worker nodes:
{{< clipboard >}}
```sh
$ sudo getenforce
```
{{< /clipboard >}}
    - If SELinux is in `enforcing` mode, then follow these steps:
       - To fix this issue, you need to override the default SELinux option in the Verrazzano Custom Resource.
       - Edit the Verrazzano CR and add the necessary SELinux options to provide read/write access to the logs directory in the Fluentd section. For example:
{{< clipboard >}}
```yaml
spec:
  components:
    fluentd:
      overrides:
      - values:
          seLinuxOptions:
            type: spc_t
```
{{< /clipboard >}}  
   {{< alert title="NOTE" color="primary" >}}The `spc_t` SELinux context is very permissive in that it gives the pod full access to the node on which it is running. If you don't want the Fluentd pod to have the `spc_t` context, consider creating a custom SELinux context type with only the required privileges on all the worker nodes instead of using `spc_t`.
   {{< /alert >}}

4. Verification.
    - Verify that Fluentd is able to read and push the logs to OpenSearch by reviewing the Fluentd logs.
    - Verify that the logs are visible in OpenSearch by accessing the OpenSearch dashboard or using relevant search queries.
