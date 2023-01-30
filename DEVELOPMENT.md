# Documentation Development Instructions

## Setup

1. Clone this repository (or your fork) using `--recurse-submodules`:

   ```shell
   git clone --recurse-submodules https://github.com/verrazzano/docs.git
   ```

   If you cloned this repository without `--recurse-submodules`, you'll
   need to run the following commands inside the repository:

   ```shell
   git submodule init
   git submodule update
   cd themes/docsy
   git submodule init
   git submodule update
   ```

   (Docsy uses two submodules, but those don't use further submodules.)

1. (Optional) If you want to change the CSS, install
   [PostCSS](https://www.docsy.dev/docs/getting-started/#install-postcss).

1. Install a supported version of [Hugo](https://www.docsy.dev/docs/getting-started/#install-hugo).

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
