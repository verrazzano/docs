---
title: "EARLY ACCESS"
weight: 1
bookHidden: true
---

# EARLY ACCESS

Welcome and thank you for your interest in participating in early
access to Verrazzano.

## Support and feedback for early access customers

You can provide feedback and ask questions at any time on our
[public slack](https://weblogic-slack-inviter.herokuapp.com/) in
the `#verrazzano` private channel.  Once you have access to the
slack workspace, send a direct message to `@Mark Nelson` to get
added to the private channel.

## Content of current code drop

The current code drop, what we call "M1" contains the following
Verrazzano components:

* Verrazzano Operator
* Verrazzano Micro-operators for:
   * OCI Service Broker
   * Coherence
   * Helidon
   * WebLogic
* Verrazzano Custom Resource Descriptor Generator
* Verrazzano Website and Documentation
* The "Bob's Books" demonstration application
* Sample code to create Kubernetes clusters in Oracle Cloud Infrastructure (OCI)
  using Oracle Linux Cloud Native Environment

{{< hint info >}}
There are additional components that will be made available in future
early access code drops before General Availability.
{{< /hint >}}

## Prerequisites

write me

### DNS requirements

Customer updates their DNS with DNS data we provide. This allows verrazzano to function as intended, including addressing individual components and issuance of valid certificates. We do so by using acme cert-manager issuer and manual DNS configuration where we create _acme-challenge. CNAME which points to acme registration server who helps us issue certificates. If we were to create a verrazzano at example0.verrazzano.io we would:

* Create `ingres.example0.verrazzano.io` A record pointing to the LB IP
* Create `*.example0.verrazzano.io` CNAME `ingress.example0.verrazzano.io`
* Create `_acme-challenge.example0.verrazano.io` CNAME `c4ff6c9c-c191-4a32-ab0b-91bc4f8f47ad.auth.acme-dns.io` (result of acme auth registration see below)

`curl -s -X POST https://auth.acme-dns.io/register | python -m json.tool`

the result have to be put into a secret keyed off of the domain name acmedns.json

```
{
   "example0.verrazano.io": {
   "allowfrom": [],
   "fulldomain": "c4ff6c9c-c191-4a32-ab0b-91bc4f8f47ad.auth.acme-dns.io",
   "password": "IW2T4Ic7snaKxKjwd602fpuiqUVeQGnXCOL7ktvF",
   "subdomain": "c4ff6c9c-c191-4a32-ab0b-91bc4f8f47ad",
   "username": "ba1a82bd-f623-4a8f-ab67-97890a411b40"
   }
 }
```

`kubectl create secret generic acme-dns --from-file acmedns.json`

Update ClusterIssuer with configuration for acmedns

```
      providers:
      - acmedns:
	  accountSecretRef:
	    key: acmedns.json
	    name: acme-dns
	  host: https://auth.acme-dns.io
	name: acmedns
```

Update cert-manager deployment with appropriate credentials location

```
spec:
  containers:
  - args:
    - --cluster-resource-namespace=$(POD_NAMESPACE)
    - --default-acme-issuer-challenge-type=dns01
    - --default-acme-issuer-dns01-provider-name=acmedns
    - --default-issuer-kind=ClusterIssuer
    - --default-issuer-name=verrazzano-dyndns-issuer
    - --renew-before-expiry-duration=360h
    - --v=6
    ...
```    


## How to install the early access code

write me

## Validating the environment

ra ra

## Installing the demo application

ra ra


## Limitations

write me
