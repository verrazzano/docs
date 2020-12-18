---
title: Verrazzano Console
weight: 5
draft: false
---

You can use the Verrazzano Console to access and manage Verrazzano components and applications deployed to a Verrazzano environment.

The Verrazzano Console repository includes:

- [hooks](scripts/hooks): The [Oracle JavaScript Extension Toolkit (JET) hooks](https://docs.oracle.com/en/middleware/developer-tools/jet/9.1/develop/customize-web-application-tooling-workflow.html#GUID-D19EC0A2-DFEF-4928-943A-F8CC08961453) used for building and running the Console application.
- [jet-composites](src/ts/jet-composites): The [Oracle JET Custom Components](https://docs.oracle.com/en/middleware/developer-tools/jet/9.1/develop/design-custom-web-components.html) which are basic building blocks for the Console.
- [views](src/ts/views) and [viewModels](src/ts/viewModels): The Oracle JET Views and ViewModels used in the Console. See [Oracle JET Architecture](https://docs.oracle.com/en/middleware/developer-tools/jet/9.1/develop/oracle-jet-architecture.html#GUID-293CB342-196F-4FC3-AE69-D1226A025FBB) for more details.
- [test](test): The tests and test-related configuration for the Console.

### Prerequisites

- [Node.js](http://nodejs.org/) 14.x+ (with [npm](https://docs.npmjs.com/cli/npm) v6.14.x+)

  To install Node.js, use [nvm](https://github.com/nvm-sh/nvm):

  ```bash
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.35.3/install.sh | bash
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    nvm install 14.7
  ```

- [Oracle JET CLI](https://github.com/oracle/ojet-cli) 9.1.x+

  The Verrazzano Console uses the [Oracle JET](https://www.oracle.com/webfolder/technetwork/jet/index.html) framework. The Oracle JET command-line interface (`ojet-cli`) is required to run Oracle JET Tooling commands, which you can install with `npm`.

  ```bash
    npm install -g @oracle/ojet-cli
  ```

  For more information, see [Getting Started with Oracle JavaScript Extension Toolkit (JET)](https://docs.oracle.com/en/middleware/developer-tools/jet/9.1/develop/getting-started-oracle-javascript-extension-toolkit-jet.html).

- An existing Verrazzano environment and access to the Verrazzano API and the Keycloak server URL.

  The Verrazzano Console requires the URL of the Keycloak server (for authentication) and the Verrazzano API Server URL (for fetching environment and application data). The format of the Verrazzano API Server URL typically is `https://verrazzano.v8o-env.v8o-domain.com` and the Keycloak server URL is `https://keycloak.v8o-env.v8o-domain.com` where:

  - `v8o-env` is the name of the Verrazzano environment and `v8o-domain.com` is the domain, when a DNS provider is used.
  - `v8o-env` is replaced by `default` and `v8o-domain.com` is the IP address of load balancer for the Kubernetes cluster, when a "magic" DNS provider like `xip.io` is used.

  For more details on installing and accessing Verrazzano, see the [installation instructions](https://github.com/verrazzano/verrazzano/blob/master/install/README.md).

### Setup

Clone the `git` repository and install `npm` dependencies:

```bash
  git clone https://github.com/verrazzano/console.git
  cd console
  nvm use 14.7
  npm install
```

#### Set up the Keycloak client

[Keycloak](https://github.com/keycloak/keycloak) provides Identity and Access Management in Verrazzano for authentication to various dashboards and the Console application. To run the Verrazzano Console locally, first you need to configure the **webui** [OpenID Connect client](https://www.keycloak.org/docs/latest/server_admin/#oidc-clients) to authenticate the login and API requests originating from the application deployed at `localhost`.

1. Access the Keycloak administration console for your Verrazzano environment: `https://keycloak.v8o-env.v8o-domain.com`
2. Log in with the Keycloak admin user and password. Typically the Keycloak admin user name is `keycloakadmin` and the password can be obtained from your management cluster:

```bash
  kubectl get secret --namespace keycloak keycloak-http -o jsonpath={.data.password} | base64 --decode; echo
```

For more information on accessing Keycloak and other user interfaces in Verrazzano, see [Get console credentials](https://github.com/verrazzano/verrazzano/blob/master/install/README.md#6-get-console-credentials).

3. Navigate to **Clients** and select the client, **webui**. On the **Settings** page, go to **Valid Redirect URIs** and select the plus (+) sign to add the redirect URL `http://localhost:8000/*`.
4. On the same page, go to **Web Origins** and select the plus (+) sign to add `http://localhost:8000`.
5. Click **Save**.

You can also set up a separate Keycloak client for local access using [these](https://www.keycloak.org/docs/latest/server_admin/#oidc-clients) instructions.

#### Get Verrazzano user credentials

Verrazzano installations have a default user `verrazzano` configured in the Verrazzano Keycloak server which can be used for authentication for accessing the Console. To get the password for the `verrazzano` user from the management cluster, run:

```bash
   kubectl get secret --namespace verrazzano-system verrazzano -o jsonpath={.data.password} | base64 --decode; echo
```

The Verrazzano Console accesses the Verrazzano API using [JSON Web Token (JWT)](https://en.wikipedia.org/wiki/JSON_Web_Token)-based authentication enabled by the [Keycloak Authorization Services](https://www.keycloak.org/docs/4.8/authorization_services/). The Console application requests this token from the Keycloak API Server. To access the Keycloak API, the user accessing the Console application must be logged in to Keycloak and have a valid session. When an existing Keycloak user session is expired or upon the expiration of the [refresh token](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/), the browser is redirected to the Keycloak login page, where you can authenticate again using the credentials for user `verrazzano`.

#### Set up environment variables

Set the following environment variables:

```bash
  export VZ_AUTH=true
  export VZ_KEYCLOAK_URL=<your Keycloak URL> e.g. https://keycloak.default.11.22.33.44.xip.io
  export VZ_UI_URL=http://localhost:8000
  export VZ_CLIENT_ID=<your client id which allows redirect uri on localhost:8000 or webui if using default>
  export VZ_API_URL=<your Verrazzano API Server URL> e.g. https://verrazzano.default.11.22.33.44.xip.io
```

#### Start server

To run the Console application in a local web server, run following command:

```bash
  ojet serve
```

This will open a browser at [http://localhost:8000](http://localhost:8000). On first access, you will be required to log in to Keycloak with the `verrazzano` user and password obtained in [Get Verrazzano user credentials](#get-verrazzano-user-credentials).

When you make changes to the Console code, the changes are reflected immediately in the browser because the `livereload` option is enabled by default for the `ojet serve` command. For other options supported by the command, see [Serve a Web Application](https://docs.oracle.com/en/middleware/developer-tools/jet/9.1/develop/serve-web-application.html#GUID-75032B22-6365-426D-A63C-33B37B1575D9).

### Testing

Unit tests for the Verrazzano Console use [Karma](https://karma-runner.github.io/latest/index.html) and [Mocha](https://mochajs.org/). For running the tests, you need the [Chrome](https://www.google.com/chrome/) browser. To run tests for the Console, run:

```bash
  make unit-test
```

Integration tests for the Verrazzano Console use [Mocha](https://mochajs.org/) and [Selenium](https://www.selenium.dev/). For running the tests, you need the [Chrome](https://www.google.com/chrome/) browser and the [chromedriver](https://chromedriver.chromium.org/) version appropriate for the version of your Chrome browser.

To run integration tests for the Console:
* Set the environment variable `VZ_UI_URL` to the URL of a running instance of the Console UI e.g. `http://localhost:8000`.
* Set the environment variable `VZ_UITEST_CONFIG` to a UI test configuration file (a sample is provided in `integtest/config.uitest.json`, which you may edit to add login information).
* Run the tests using the following command:
```
npm run integtest
```

### Building

To build the Console, run the following commands:

- Oracle JET build:

  ```
  make ojet-build
  ```

- Docker build:
  ```
  make build
  ```

### Linting

[ESLint](https://eslint.org/) and [prettier](https://prettier.io/) are used to keep the code style consistent.
To run linting locally:

```
npm run eslint
```

Check the formatting of your code using prettier:

```
npm run prettier
```

To format your code using prettier:

```
npm run prettier-write
```
