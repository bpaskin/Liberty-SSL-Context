# Liberty SSL Access

A working example of four different ways to access and use the SSL configuration from within a Liberty servlet — useful when your code needs the `SSLContext`, underlying SSL properties, or needs to make outbound HTTPS calls with a specific client certificate at runtime.

---

## Overview

For security reasons, Liberty does not expose keystore paths or passwords as plain system properties. The SSL configuration lives inside `server.xml` under the `<ssl>` element. This project demonstrates how application code can reach that configuration using two read approaches and two outbound-call approaches:

| Approach | Servlet | Endpoint |
|---|---|---|
| **JSSEHelper** — read config by name | `SSLInfoServlet` | `GET /sslinfo` |
| **JMX discovery** — read all configs dynamically | `SSLInfoServletJMX` | `GET /sslinfojmx` |
| **Outbound HTTPS call** — hardcoded SSL id + cert alias | `SSLClientCallServlet` | `GET /sslcall` |
| **Outbound HTTPS call** — SSL id + cert alias resolved via JMX | `SSLClientCallServletJMX` | `GET /sslcalljmx` |

---

## Endpoints

### `GET /sslinfo`
Uses `JSSEHelper.getProperties("defaultSSLConfig")` to fetch the SSL properties for the well-known default config name. Simple and fast, but requires knowing the config `id` in advance. Responds with plain-text listing of all resolved SSL properties.

### `GET /sslinfojmx`
Discovers all `<ssl>` entries dynamically at runtime:
1. Locates the OSGi `ConfigurationAdminMBean` via JMX.
2. Queries all entries with factory PID `com.ibm.ws.ssl.repertoire`.
3. Reads the `id` attribute from each entry's OSGi config properties.
4. Calls `JSSEHelper.getProperties(id)` for each discovered config.

This approach works even when the config `id` is unknown or when there are multiple SSL configurations.

### `GET /sslcall`
Makes an outbound HTTPS call using a specific client certificate alias:
1. Loads SSL properties for `defaultSSLConfig` via `JSSEHelper`.
2. Overrides `com.ibm.ssl.keyStoreClientAlias` with the hardcoded alias `clientCert`.
3. Builds an `SSLContext` and opens an `HttpsURLConnection` to the target URL.

The SSL config id and cert alias are compile-time constants — straightforward when the configuration is stable.

### `GET /sslcalljmx`
Same outbound HTTPS call as `/sslcall`, but the SSL config `id` and `clientKeyAlias` are resolved at runtime via JMX instead of being hardcoded:
1. Locates the `ConfigurationAdminMBean` via JMX.
2. Queries factory PID `com.ibm.ws.ssl.repertoire` and picks the first `<ssl>` entry.
3. Reads `id` and `clientKeyAlias` from the entry's OSGi config properties.
4. Falls back to `Constants.DEFAULT_CERTIFICATE_ALIAS` (`"default"`) if `clientKeyAlias` is absent.
5. Builds an `SSLContext` and makes the outbound call.

---

## Keystore

The project ships a PKCS12 keystore at `src/main/liberty/config/resources/security/key.p12` (password: `password`) with two entries:

| Alias | Subject CN | Purpose |
|---|---|---|
| `default` | `localhost` | Inbound TLS — Liberty server identity certificate |
| `clientCert` | `client` | Outbound TLS — client certificate presented on outbound calls |

Both are self-signed RSA 2048-bit certificates valid for 10 years. For production use, replace them with CA-signed certificates.

To inspect the keystore contents:
```bash
keytool -list -v \
  -keystore src/main/liberty/config/resources/security/key.p12 \
  -storepass password \
  -storetype PKCS12
```

---

## SSL Configuration (`server.xml`)

```xml
<ssl id="defaultSSLConfig"
     keyStoreRef="defaultKeyStore"
     trustStoreRef="defaultTrustStore"
     sslProtocol="TLSv1.3"
     enabledCiphers="TLS_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256"
     clientKeyAlias="clientCert"
     clientAuthenticationSupported="true"/>
```

| Attribute | Value | Meaning |
|---|---|---|
| `sslProtocol` | `TLSv1.3` | Only TLS 1.3 accepted |
| `enabledCiphers` | AES-256 / AES-128 GCM | Only these two TLS 1.3 cipher suites |
| `clientKeyAlias` | `clientCert` | Alias used when Liberty presents a client cert on **outbound** calls |
| `clientAuthenticationSupported` | `true` | Accepts an inbound client cert if presented but does not require one |

> **Note:** `clientAuthentication="true"` would enforce mTLS on every inbound connection and reject browsers/clients that do not present a certificate (`CWWKO0801E: Empty client certificate chain`). Use `clientAuthenticationSupported="true"` to allow but not require client certs.

---

## Prerequisites

- Java 17+
- Maven 3.8+

---

## Build & Run

```bash
# Build and start Liberty in dev mode (hot reload)
mvn liberty:dev
```

```bash
# Build and start Liberty normally
mvn liberty:run
```

The server starts on:
- HTTP  → `http://localhost:9080`
- HTTPS → `https://localhost:9443`

---

## Try It

```bash
# Read SSL properties — JSSEHelper by config name
curl -k https://localhost:9443/sslinfo

# Read SSL properties — JMX discovery (all SSL configs)
curl -k https://localhost:9443/sslinfojmx

# Outbound HTTPS call — hardcoded SSL id + cert alias
curl -k https://localhost:9443/sslcall

# Outbound HTTPS call — SSL id + cert alias resolved via JMX
curl -k https://localhost:9443/sslcalljmx
```

> `-k` skips hostname verification for the self-signed `default` cert on localhost.

---

## Project Structure

```
src/
  main/
    java/com/ibm/example/servlet/
      SSLInfoServlet.java           # Read SSL properties via JSSEHelper (by name)
      SSLInfoServletJMX.java        # Read SSL properties via JMX discovery
      SSLClientCallServlet.java     # Outbound HTTPS call, hardcoded SSL id + alias
      SSLClientCallServletJMX.java  # Outbound HTTPS call, SSL id + alias from JMX
    liberty/config/
      server.xml                    # Liberty config (TLS 1.3, PKCS12 keystore)
      resources/security/
        key.p12                     # PKCS12 keystore (aliases: default, clientCert)
pom.xml
```

---

## References

- [Liberty SSL defaults — IBM Documentation](https://www.ibm.com/docs/en/was-liberty/base?topic=liberty-ssl-defaults-in)
- [JSSEHelper API](https://www.ibm.com/docs/en/was-liberty/base?topic=SSEQTP_liberty/com.ibm.websphere.javadoc.liberty.doc/com.ibm.websphere.appserver.api.ssl_1.9-javadoc/com/ibm/websphere/ssl/JSSEHelper.html)
- [Liberty Maven Plugin](https://github.com/OpenLiberty/ci.maven)
