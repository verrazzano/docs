---
title: "Bob's Books Example Application"
weight: 2
---

Bob's Books consists of three main parts:

* A back-end "order processing" application, which is a Java EE
  application with REST services and a very simple JSP UI, which
  stores data in a MySQL database.  This application runs on WebLogic
  Server.
* A front-end web store "Robert's Books", which is a general book
  seller.  This is implemented as a Helidon microservice, which
  gets book data from Coherence, uses a Coherence cache store to persist
  data for the order manager, and has a React web UI.
* A front-end web store "Bobby's Books", which is a specialty
  children's book store.  This is implemented as a Helidon
  microservice, which gets book data from a (different) Coherence cache store,
  interfaces directly with the order manager,
  and has a JSF web UI running on WebLogic Server.

To deploy the application, see [Bob's Books](https://github.com/verrazzano/verrazzano/blob/master/examples/bobs-books/README.md).

The Bob's Books example application is located in the repository [`https://github.com/verrazzano/examples`](https://github.com/verrazzano/examples).
