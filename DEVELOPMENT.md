# Documentation Development Instructions

## Prerequisites

1. Install [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git).

1. Install the extended edition of [Hugo](https://gohugo.io/installation/) for your platform.

1. Install [Go](https://go.dev/dl/).

1. Clone this repository (or your fork):

   ```shell
   git clone https://github.com/verrazzano/docs.git
   ```

## Run locally

Run a local Hugo server with live reloading.

```
hugo server --environment local
```

Access the local Hugo server to see the rendered docs.  The rendered docs will refresh when you save your edits.

```
open http://localhost:1313
```

## Update Generated API Reference Documentation

To update the generated API reference documentation follow these steps:

1. Check out a docs repo feature branch.
```
git checkout -b <branch-name>
```

2. Run a `Makefile` target to generate the API reference documentation.
Specify the verrazzano repo branch from which to generate the documentation.
```
make generate-api BRANCH=<branch-name>
```

3. If new versions of the API reference documentation are generated, then commit those changes, push the changes,
and submit a pull request.
