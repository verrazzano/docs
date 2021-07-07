---
title: "Customizing Certificates"
description: "Customizing SSL certificate generation for Verrazzano system and application endpoints"
weight: 2
draft: true
---

This document describes how to configure SSL certificates for use with Verrazzano services and deployed applications.

Verrazzano can be configured to issue certificates to secure external access to the system and application endpoints in
the following configurations:

* Using a self-signed CA created by Verrazzano
* Using staging or production LetsEncrypt certificates
* Providing your own certificates

