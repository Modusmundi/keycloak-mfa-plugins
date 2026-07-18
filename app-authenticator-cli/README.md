# App Authenticator CLI

> **Status: not maintained.** Like its server-side counterpart, the [App
> Authenticator](../app-authenticator/README.md), this reference client is kept in the tree for
> reference only.

A Node.js reference implementation of the client-side logic of the [App Authenticator](../app-authenticator/README.md), useful for exercising the API without a mobile app.

## Usage

```shell
npm install
node authenticator.js setup   # register a new authenticator from an activation token URL
node authenticator.js auth    # poll for a pending login challenge and accept or reject it
```

`setup` prompts for the activation token URL shown in the Keycloak account console, generates an asymmetric keypair and registers the authenticator. `auth` fetches an open login challenge and replies to it. The generated keys and IDs are stored in `data.json` next to the script.

## Request signing

The server authenticates API requests with a custom `Signature` HTTP header, a comma-separated list of `key:value` pairs:

-   `keyId`: the authenticator ID chosen at setup, which identifies the registered public key.
-   `created`: the signing timestamp in milliseconds. The server rejects timestamps more than 10 seconds in the future.
-   `secret` and `granted`: only when replying to a login challenge — the challenge value and whether the login was approved.
-   `signature`: the Base64-encoded signature over the other pairs, created with the private key generated at setup.

For fetching challenges and updating the push ID, the signed data is the `created` pair; for challenge replies it is the `created`, `secret` and `granted` pairs. The endpoint reference, including a full header example, is in the [App Authenticator README](../app-authenticator/README.md#authentication).

The keypair uses one of the Java platform's standard [KeyFactory](https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keyfactory-algorithms) and [Signature](https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#signature-algorithms) algorithms; the public key is registered X.509-encoded during setup.

Note: `authenticator.js` still signs requests with a JWT in an `x-signature` header, an earlier scheme the current server no longer accepts. The script needs to be ported to the `Signature` header format before it can talk to a current server.
