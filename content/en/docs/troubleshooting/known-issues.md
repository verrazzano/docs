---
title: Known Issues
weight: 3
draft: true
---


#### OKE Missing Security List Ingress Rules

The install scripts perform a check, which attempts access through the ingress ports.  If the check fails, then the installation will exit and you will see error messages like this:

`ERROR: Port 443 is NOT accessible on ingress(132.145.66.80)!  Check that security lists include an ingress rule for the node port 31739.`

On an OKE install, this may indicate that there is a missing ingress rule or rules.  To verify and fix the issue, do the following:
  1. Get the ports for the `LoadBalancer` services.
     * Run `kubectl get services -A`.
     * Note the ports for the `LoadBalancer` type services.  For example `80:31541/TCP,443:31739/TCP`.
  2. Check the security lists in the Oracle Cloud Infrastructure Console.
     * Go to `Networking/Virtual Cloud Networks`.
     * Select the related VCN.
     * Go to the `Security Lists` for the VCN.
     * Select the security list named `oke-wkr-...`.
     * Check the ingress rules for the security list.  There should be one rule for each of the destination ports named in the `LoadBalancer` services.  In the previous example, the destination ports are `31541` & `31739`. We would expect the ingress rule for `31739` to be missing because it was named in the `ERROR` output.
     * If a rule is missing, then add it by clicking `Add Ingress Rules` and filling in the source CIDR and destination port range (missing port).  Use the existing rules as a guide.
