# Liberty SSL Access

A working example of two different ways to access the SSL configuration from within a Liberty servlet — useful when your code needs the `SSLContext` or underlying SSL properties at runtime.

---

## Overview

For security reasons, Liberty does not expose keystore paths or passwords as plain system properties. The SSL configuration lives inside `server.xml` under the `<ssl>` element. This project demonstrates how application code can reach that configuration using two different approaches:

| Approach | Servlet | Endpoint |
|---|---|---|
| **JSSEHelper** (direct, by name) | `SSLInfoServlet` | `GET /sslinfo` |
| **JMX discovery** (dynamic, any config) | `SSLInfoServletJMX` | `GET /sslinfojmx` |

Both servlets respond with plain-text output listing all resolved SSL properties.

---

## Endpoints

### `GET /sslinfo`
Uses `JSSEHelper.getProperties("defaultSSLConfig")` to fetch the SSL properties for the well-known default config name. Simple and fast, but requires knowing the config `id` in advance.

### `GET /sslinfojmx`
Discovers all `<ssl>` entries dynamically at runtime:
1. Locates the OSGi `ConfigurationAdminMBean` via JMX.
2. Queries all entries with factory PID `com.ibm.ws.ssl.repertoire`.
3. Reads the `id` attribute from each entry's OSGi config properties.
4. Calls `JSSEHelper.getProperties(id)` for each discovered config.

This approach works even when the config `id` is unknown or when there are multiple SSL configurations.

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
# Method 1 — JSSEHelper by config name
curl http://localhost:9080/sslinfo

# Method 2 — JMX discovery (all SSL configs)
curl http://localhost:9080/sslinfojmx
```

---

## Project Structure

```
src/
  main/
    java/com/ibm/example/servlet/
      SSLInfoServlet.java       # JSSEHelper approach
      SSLInfoServletJMX.java    # JMX discovery approach
    liberty/config/
      server.xml                # Liberty config (TLS 1.3, PKCS12 keystore)
pom.xml
```

---

## References

- [Liberty SSL defaults — IBM Documentation](https://www.ibm.com/docs/en/was-liberty/base?topic=liberty-ssl-defaults-in)
- [JSSEHelper API](https://www.ibm.com/docs/en/was-liberty/base?topic=SSEQTP_liberty/com.ibm.websphere.javadoc.liberty.doc/com.ibm.websphere.appserver.api.ssl_1.9-javadoc/com/ibm/websphere/ssl/JSSEHelper.html)
- [Liberty Maven Plugin](https://github.com/OpenLiberty/ci.maven)
