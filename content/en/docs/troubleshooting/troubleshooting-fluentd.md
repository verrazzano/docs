---
title: "Fluentd"
linkTitle: "Fluentd"
description: "Troubleshoot Fluentd issues"
weight: 3
draft: false
---


### Issue: Fluentd's Inability to Push Logs to Opensearch

If you are unable to see logs in Opensearch, it may be due to Fluentd not being able to push the logs to Opensearch. To troubleshoot this issue, follow the steps below:

1. Check Fluentd Pod Logs:
    - Identify the Fluentd pod related to the Verrazzano installation.
    - View the logs of the Fluentd pod using the following command:
      ```
      kubectl logs <fluentd-pod-name> -n verrazzano-system
      ```

2. Check for Error Description:
    - Look for the error message in the Fluentd pod logs.
    - If you see an error with the following description: 
      ```
      unexpected error error_class=Errno::EACCES error="Permission denied @ rb_sysopen - /var/log/vz-fluentd-containers.log.pos", it indicates a permission issue. Fluentd doesn't have enough privilege to write `.pos` file.
      ```
3. Resolve Permission Issue:
    - The issue occurs when SELinux is **enforcing** on the worker nodes, and Fluentd does not have the appropriate SELinux context to have read/write access to the logs directory.
    - To fix this issue, you need to override the default SELinux option in the Verrazzano Custom Resource Definition (CRD).
    - Edit the Verrazzano CRD YAML file and add the necessary SELinux options to provide read/write access to the logs directory in the Fluentd section. For example:
      ```
      spec:
        components:
          fluentd:
            overrides:
            - values:
                seLinuxOptions:
                  type: spc_t
      ```
   {{< alert title="NOTE" color="warning" >}} `spc_t` SELinux context is too permissive as it gives the pod full access of the node on which it is running than it needs. If you don't want Fluentd pod to have `spc_t` context, consider to create custom SELinux context type with required privileges on all worker nodes and use that instead of `spc_t`.
   {{< /alert >}}

4. Verification:
    - Verify that Fluentd is able to read and push the logs to Opensearch by looking at the Fluentd logs.
    - Verify that the logs are visible in Opensearch by accessing the Opensearch dashboard or using relevant search queries.

If the issue persists, or you encounter any other problems, please reach out to us for further assistance.
