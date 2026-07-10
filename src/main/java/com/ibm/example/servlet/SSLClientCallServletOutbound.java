package com.ibm.example.servlet;

import com.ibm.websphere.ssl.Constants;
import com.ibm.websphere.ssl.JSSEHelper;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.management.openmbean.CompositeData;
import javax.management.openmbean.TabularData;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Servlet that makes an outbound HTTPS call using a client certificate alias,
 * where the SSL config is resolved strictly via <sslDefault> outboundSSLRef.
 *
 * JMX resolution:
 *   1. Locates the OSGi ConfigurationAdminMBean.
 *   2. Reads the singleton <sslDefault> element (PID com.ibm.ws.ssl.sslDefault)
 *      — returns an error if <sslDefault> is not present.
 *   3. Extracts the "outboundSSLRef" attribute from <sslDefault>
 *      — returns an error if the attribute is absent.
 *   4. Scans all <ssl> elements (factory PID com.ibm.ws.ssl.repertoire) and
 *      selects the one whose "id" matches the outboundSSLRef value
 *      — returns an error if no match is found.
 *   5. Reads "id" and "clientKeyAlias" from the matched <ssl> element.
 *   6. Builds an SSLContext using JSSEHelper.
 *   7. Makes the outbound HTTPS call.
 *   8. Writes the result to the response.
 */
@WebServlet("/sslcalloutbound")
public class SSLClientCallServletOutbound extends HttpServlet {

    private static final Logger LOG = Logger.getLogger(SSLClientCallServletOutbound.class.getName());

    /** Target HTTPS endpoint to call. */
    private static final String TARGET_URL = "https://ibm.com";

    /** Liberty OSGi ConfigurationAdminMBean object name pattern */
    private static final String CONFIG_ADMIN_OBJECT_NAME = "osgi.compendium:service=cm,version=1.3,*";

    /** Liberty internal factory PID for <ssl> configuration elements */
    private static final String SSL_FACTORY_PID = "com.ibm.ws.ssl.repertoire";

    /** Liberty singleton PID for the <sslDefault> element */
    private static final String SSL_DEFAULT_PID = "com.ibm.ws.ssl.default";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        LOG.fine("doGet invoked");

        // --- Step 1: locate the ConfigurationAdminMBean ---
        MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
        ObjectName configAdminMBean;
        try {
            Set<ObjectName> names = mbs.queryNames(new ObjectName(CONFIG_ADMIN_OBJECT_NAME), null);
            LOG.fine("ConfigurationAdminMBean candidates found: " + names.size());
            if (names.isEmpty()) {
                LOG.warning("OSGi ConfigurationAdminMBean not found");
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "OSGi ConfigurationAdminMBean not found — is monitor-1.0 feature enabled?");
                return;
            }
            configAdminMBean = names.iterator().next();
            LOG.fine("Using ConfigurationAdminMBean: " + configAdminMBean);
        } catch (Exception e) {
            LOG.warning("Failed to locate ConfigurationAdminMBean: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to locate ConfigurationAdminMBean: " + e.getMessage());
            return;
        }

        // --- Step 2: read <sslDefault> — error if not found ---
        TabularData defaultProps = null;
        try {
            LOG.fine("Querying <sslDefault> singleton via service.pid filter: " + SSL_DEFAULT_PID);
            String[][] defaultConfigs = (String[][]) mbs.invoke(
                    configAdminMBean,
                    "getConfigurations",
                    new Object[]{ "(service.pid=" + SSL_DEFAULT_PID + ")" },
                    new String[]{ String.class.getName() });

            if (defaultConfigs == null || defaultConfigs.length == 0) {
                LOG.warning("<sslDefault> element not found in OSGi configuration");
                response.sendError(HttpServletResponse.SC_NOT_FOUND,
                        "<sslDefault> element not found — ensure it is declared in server.xml");
                return;
            }

            String defaultPid = defaultConfigs[0][0];
            LOG.fine("<sslDefault> runtime pid token: " + defaultPid);
            defaultProps = (TabularData) mbs.invoke(
                    configAdminMBean,
                    "getProperties",
                    new Object[]{ defaultPid },
                    new String[]{ String.class.getName() });

            if (defaultProps == null) {
                LOG.warning("<sslDefault> getProperties returned null for pid token: " + defaultPid);
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "<sslDefault> properties could not be read from OSGi configuration");
                return;
            }
        } catch (Exception e) {
            LOG.warning("<sslDefault> query failed: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "<sslDefault> query failed: " + e.getMessage());
            return;
        }

        // --- Step 3: extract outboundSSLRef — error if absent ---
        CompositeData outboundRow = defaultProps.get(new Object[]{ "outboundSSLRef" });
        if (outboundRow == null) {
            LOG.warning("<sslDefault> does not contain an outboundSSLRef attribute");
            response.sendError(HttpServletResponse.SC_NOT_FOUND,
                    "<sslDefault> found but outboundSSLRef attribute is missing — "
                    + "add outboundSSLRef=\"<ssl-id>\" to the <sslDefault> element in server.xml");
            return;
        }
        String outboundSSLRef = (String) outboundRow.get("Value");
        LOG.fine("<sslDefault> outboundSSLRef = " + outboundSSLRef);

        // --- Step 4: scan all <ssl> entries and match outboundSSLRef — error if not found ---
        String[][] sslConfigs;
        try {
            LOG.fine("Querying all <ssl> entries with factory PID: " + SSL_FACTORY_PID);
            sslConfigs = (String[][]) mbs.invoke(
                    configAdminMBean,
                    "getConfigurations",
                    new Object[]{ "(service.factoryPid=" + SSL_FACTORY_PID + ")" },
                    new String[]{ String.class.getName() });
            LOG.fine("Found " + (sslConfigs == null ? 0 : sslConfigs.length) + " <ssl> configuration(s)");
        } catch (Exception e) {
            LOG.warning("Failed to query SSL configurations via JMX: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to query SSL configurations via JMX: " + e.getMessage());
            return;
        }

        String targetPid = null;
        if (sslConfigs != null) {
            for (String[] entry : sslConfigs) {
                try {
                    TabularData props = (TabularData) mbs.invoke(
                            configAdminMBean,
                            "getProperties",
                            new Object[]{ entry[0] },
                            new String[]{ String.class.getName() });
                    CompositeData idRow = props.get(new Object[]{ "id" });
                    if (idRow != null && outboundSSLRef.equals(idRow.get("Value"))) {
                        targetPid = entry[0];
                        LOG.fine("Matched <ssl> id='" + outboundSSLRef + "' at OSGi pid=" + targetPid);
                        break;
                    }
                } catch (Exception e) {
                    LOG.fine("Skipping unreadable <ssl> entry pid=" + entry[0] + ": " + e.getMessage());
                }
            }
        }

        if (targetPid == null) {
            LOG.warning("No <ssl> entry found with id matching outboundSSLRef='" + outboundSSLRef + "'");
            response.sendError(HttpServletResponse.SC_NOT_FOUND,
                    "No <ssl id=\"" + outboundSSLRef + "\"> element found — "
                    + "ensure an <ssl> element with that id is declared in server.xml");
            return;
        }

        // --- Step 5: read "id" and "clientKeyAlias" from the matched <ssl> config ---
        String sslId = null;
        String clientAlias = Constants.DEFAULT_CERTIFICATE_ALIAS; // fallback if not set
        LOG.fine("Reading properties from targetPid=" + targetPid);
        try {
            TabularData configProps = (TabularData) mbs.invoke(
                    configAdminMBean,
                    "getProperties",
                    new Object[]{ targetPid },
                    new String[]{ String.class.getName() });

            CompositeData idRow = configProps.get(new Object[]{ "id" });
            if (idRow != null) {
                sslId = (String) idRow.get("Value");
                LOG.fine("Resolved ssl id='" + sslId + "'");
            }

            CompositeData aliasRow = configProps.get(new Object[]{ "clientKeyAlias" });
            if (aliasRow != null) {
                clientAlias = (String) aliasRow.get("Value");
                LOG.fine("Resolved clientKeyAlias='" + clientAlias + "'");
            } else {
                LOG.fine("No 'clientKeyAlias' attribute found; using default alias='" + clientAlias + "'");
            }
        } catch (Exception e) {
            LOG.warning("Failed to read SSL config properties for pid=" + targetPid + ": " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to read SSL config properties via JMX: " + e.getMessage());
            return;
        }

        if (sslId == null) {
            LOG.warning("Could not determine SSL config id from JMX for pid=" + targetPid);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Could not determine SSL config id from JMX");
            return;
        }

        // --- Step 6: build SSLContext using the JMX-resolved id and alias ---
        LOG.fine("Building SSLContext for id='" + sslId + "' alias='" + clientAlias + "'");
        SSLContext sslContext;
        try {
            Properties sslProps = JSSEHelper.getInstance().getProperties(sslId);
            sslProps.setProperty(Constants.SSLPROP_KEY_STORE_CLIENT_ALIAS, clientAlias);
            sslContext = JSSEHelper.getInstance().getSSLContext(null, sslProps);
            LOG.fine("SSLContext built successfully");
        } catch (Exception e) {
            LOG.warning("Failed to build SSLContext for id='" + sslId + "' alias='" + clientAlias + "': " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to build SSLContext for id='" + sslId + "' alias='" + clientAlias + "': " + e.getMessage());
            return;
        }

        // --- Step 7: make the outbound HTTPS call ---
        LOG.fine("Opening HTTPS connection to " + TARGET_URL);
        String responseBody;
        int statusCode;
        try {
            HttpsURLConnection conn = (HttpsURLConnection) URI.create(TARGET_URL).toURL().openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5_000);
            conn.setReadTimeout(10_000);
            statusCode = conn.getResponseCode();
            LOG.fine("Outbound HTTP status: " + statusCode);
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                responseBody = reader.lines().collect(Collectors.joining("\n"));
            }
        } catch (IOException e) {
            LOG.warning("Outbound HTTPS call to '" + TARGET_URL + "' failed: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_BAD_GATEWAY,
                    "Outbound HTTPS call to '" + TARGET_URL + "' failed: " + e.getMessage());
            return;
        }

        // --- Step 8: write the result ---
        response.setContentType("text/plain;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        try (PrintWriter out = response.getWriter()) {
            out.printf("outboundSSLRef (from sslDefault) : %s%n", outboundSSLRef);
            out.printf("SSL config id  (from JMX)        : %s%n", sslId);
            out.printf("Cert alias     (from JMX)        : %s%n", clientAlias);
            out.printf("Target URL                       : %s%n", TARGET_URL);
            out.printf("HTTP status                      : %d%n%n", statusCode);
            out.println("--- Response body ---");
            out.println(responseBody);
        }
    }
}
