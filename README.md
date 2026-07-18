# Keycloak MFA Plugin collection

This repository contains the source code for a collection of Keycloak MFA plugins:

* [SMS authenticator](sms-authenticator/README.md): Provides SMS as authentication step. Messages are sent via a configurable HTTP API. (production ready)
* [Email authenticator](email-authenticator/README.md): Provides Email OTP as authentication step. Uses the SMTP server configured in the realm. (production ready)
* [Enforce MFA](enforce-mfa/README.md): Force users to configure a second factor after logging in. (beta)
* [Native App MFA integration](app-authenticator/README.md): Connect a mobile app to Keycloak which receives a notification about a pending login and lets the user approve or reject it. (work in progress)

Two further directories support the plugins:

* [mfa-dev-runner](mfa-dev-runner/README.md): Runs a local Keycloak in Quarkus dev mode with all plugins deployed.
* [app-authenticator-cli](app-authenticator-cli/README.md): A Node.js reference client for the app authenticator API. Not part of the Maven build.

Each plugin is documented in its own README. If you need support for deployment or adjustments, please contact [support@verdigado.com](mailto:support@verdigado.com).

Changes are tracked in the [CHANGELOG](CHANGELOG.md). See [SECURITY.md](SECURITY.md) for how to report vulnerabilities and [SECURITY-AUDIT.md](SECURITY-AUDIT.md) for a recorded security review of the SMS authenticator.

## License

The code of this project is Apache 2.0 licensed. Parts of the original code are MIT licensed.

## Building

You need JDK 17 and Apache Maven (the repository does not ship a Maven wrapper). The plugins are built against the Keycloak version set in the `keycloak.version` property of the parent `pom.xml`.

```shell
mvn clean install
```

Each module writes its jar to its own `target` directory, named `netzbegruenung.<module>-v<version>.jar`, for example `sms-authenticator/target/netzbegruenung.sms-authenticator-v26.6.5.jar`.

## Development

The [MFA dev runner](mfa-dev-runner/README.md) starts a Keycloak dev server with all plugins deployed and supports hot reload.

## Releases

Releases are built by the GitHub Actions workflow [`release.yml`](.github/workflows/release.yml), triggered by pushing a tag that starts with `v`. A release contains the jar of each plugin module along with a `.sha512` checksum and a cosign signature (`.sig` and `.pem`) per jar.

To cut a release you need the access rights to push protected tags, see the [GitHub documentation on tag protection rules](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/configuring-tag-protection-rules#about-tag-protection-rules).

1. Update project and module versions: `mvn versions:set -DnewVersion=1.2.3; mvn versions:commit`
2. Commit your changes.
3. Tag the commit. The `awk` filter strips ANSI escape codes from the Maven output:
   ```shell
   VERSION=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout \
     | awk '{gsub(/\x1b\[[0-9;]*[mK]/,""); print}' \
     | tr -d '\r')
   git tag -a "v$VERSION" -m "Bump version $VERSION"
   ```
4. Trigger the release with `git push --tags`

After the workflow completes, the new release is available on the repository's releases page with the signed jar files for each module.
