---
title: "Fluentd"
linkTitle: "Fluentd"
description: "Troubleshoot Fluentd permission issue when SELinux mode is enforcing"
weight: 3
draft: false
---


### Issue: Fluentd's Inability to Push Logs to OpenSearch due to permission issue when SELinux mode is enforcing

If you are unable to see logs in OpenSearch, it may be due to a permission issue in Fluentd when SELinux mode is enforcing, preventing it from being able to push the logs to OpenSearch. To troubleshoot the Fluentd permission issue, follow the steps mentioned below:

1. Check Fluentd Pod Logs:
    - Identify the Fluentd pod related to the Verrazzano installation.
    - View the logs of the Fluentd pod using the following command:
      ```
      kubectl logs <fluentd-pod-name> -n verrazzano-system
      ```

2. Check for Error Description:
    - Look for the error message in the Fluentd pod logs.
    - If you see an error with the following description, follow the steps mentioned in the Resolve Permission Issue section.: 
      ```
      unexpected error error_class=Errno::EACCES error="Permission denied @ rb_sysopen - /var/log/vz-fluentd-containers.log.pos", it indicates a permission issue. Fluentd doesn't have enough privilege to write `.pos` file.
      ```
3. Resolve Permission Issue:
    - The issue occurs when SELinux is **enforcing** on the worker nodes, and Fluentd does not have the appropriate SELinux context to have read/write access to the logs directory.
    - Check if SELinux is **enforcing** by running the command: `sudo getenforce` on the worker nodes. If SELinux is `enforcing`, follow the below steps.
    - To fix this issue, you need to override the default SELinux option in the Verrazzano Custom Resource.
    - Edit the Verrazzano CR and add the necessary SELinux options to provide read/write access to the logs directory in the Fluentd section. For example:
      ```
      spec:
        components:
          fluentd:
            overrides:
            - values:
                seLinuxOptions:
                  type: spc_t
      ```
   {{< alert title="NOTE" color="warning" >}} `spc_t` SELinux context is quite permissive as it gives the pod full access to the node on which it is running than it needs. If you don't want Fluentd pod to have `spc_t` context, consider to create custom SELinux context type with required privileges on all worker nodes and use that instead of `spc_t`.
   {{< /alert >}}

4. Verification:
    - Verify that Fluentd is able to read and push the logs to OpenSearch by looking at the Fluentd logs.
    - Verify that the logs are visible in OpenSearch by accessing the OpenSearch dashboard or using relevant search queries.

If the issue persists, or you encounter any other problems, please reach out to us for further assistance.
