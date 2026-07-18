# MFA Dev Runner

This module contains no source code. It runs a Keycloak server as a Quarkus application in dev mode, with all MFA plugins from this repository on the classpath, so you can work on the plugins without building jars and copying them into a `providers` directory.

Its `pom.xml` depends on the `sms-authenticator`, `email-authenticator`, `app-authenticator` and `enforce-mfa` modules plus `keycloak-quarkus-server`, and configures the `quarkus-maven-plugin` to launch the server. Source changes in the plugin modules are picked up by Quarkus hot reload, and you can attach a Java debugger to the running process.

## Usage

Start the server from the root of the repository:

```bash
mvn -f mfa-dev-runner/pom.xml compile quarkus:dev
```

The Keycloak start arguments (including the database connection) are set in the `<argsString>` of the `quarkus-maven-plugin` configuration in this module's `pom.xml`.

For details on how Keycloak runs as a Quarkus application, see the [Keycloak developer documentation](https://github.com/keycloak/keycloak/blob/main/quarkus/CONTRIBUTING.md).

## Database access

The development server uses an H2 file-based database located at `h2db/mfa` in the repository root. While the server is running, you can connect to it to inspect data.

The following command picks the H2 driver version from the project's dependency tree and launches the H2 command-line shell:

```bash
H2_VERSION=$(mvn -f pom.xml dependency:tree -Dincludes=com.h2database:h2 -Dverbose | grep 'com.h2database:h2:jar:' | head -n 1 | cut -d: -f4)
java -cp ~/.m2/repository/com/h2database/h2/$H2_VERSION/h2-$H2_VERSION.jar org.h2.tools.Shell -url "jdbc:h2:file:./h2db/mfa;AUTO_SERVER=TRUE" -user sa -password password
```

Once connected, you can run SQL queries at the `sql>` prompt.
