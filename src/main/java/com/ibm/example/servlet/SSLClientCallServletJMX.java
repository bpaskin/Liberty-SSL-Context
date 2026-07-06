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
import java.util.stream.Collectors;

/**
 * Servlet that makes an outbound HTTPS call using a client certificate alias,
 * where both the SSL config id and the client cert alias are resolved at runtime
 * via the OSGi ConfigurationAdminMBean (JMX) rather than hardcoded constants.
 *
 * JMX resolution:
 *   - Queries factory PID com.ibm.ws.ssl.repertoire for all <ssl> elements
 *   - Reads the "id" and "clientKeyAlias" attributes from the first entry found
 *   - Falls back to Constants.DEFAULT_CERTIFICATE_ALIAS if clientKeyAlias is absent
 */
@WebServlet("/sslcalljmx")
public class SSLClientCallServletJMX extends HttpServlet {

    /** Target HTTPS endpoint to call. */
    private static final String TARGET_URL = "https://ibm.com";

    /** Liberty OSGi ConfigurationAdminMBean object name pattern */
    private static final String CONFIG_ADMIN_OBJECT_NAME = "osgi.compendium:service=cm,version=1.3,*";

    /** Liberty internal factory PID for <ssl> configuration elements */
    private static final String SSL_FACTORY_PID = "com.ibm.ws.ssl.repertoire";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // --- Step 1: locate the ConfigurationAdminMBean ---
        MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
        ObjectName configAdminMBean;
        try {
            Set<ObjectName> names = mbs.queryNames(new ObjectName(CONFIG_ADMIN_OBJECT_NAME), null);
            if (names.isEmpty()) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        "OSGi ConfigurationAdminMBean not found — is monitor-1.0 feature enabled?");
                return;
            }
            configAdminMBean = names.iterator().next();
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to locate ConfigurationAdminMBean: " + e.getMessage());
            return;
        }

        // --- Step 2: query all <ssl> entries and pick the first one ---
        String[][] sslConfigs;
        try {
            sslConfigs = (String[][]) mbs.invoke(
                    configAdminMBean,
                    "getConfigurations",
                    new Object[]{ "(service.factoryPid=" + SSL_FACTORY_PID + ")" },
                    new String[]{ String.class.getName() });
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to query SSL configurations via JMX: " + e.getMessage());
            return;
        }

        if (sslConfigs == null || sslConfigs.length == 0) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND,
                    "No SSL configurations found with factory PID: " + SSL_FACTORY_PID);
            return;
        }

        // --- Step 3: read "id" and "clientKeyAlias" from the OSGi config properties ---
        String sslId = null;
        String clientAlias = Constants.DEFAULT_CERTIFICATE_ALIAS; // fallback
        try {
            String pid = sslConfigs[0][0];
            TabularData configProps = (TabularData) mbs.invoke(
                    configAdminMBean,
                    "getProperties",
                    new Object[]{ pid },
                    new String[]{ String.class.getName() });

            CompositeData idRow = configProps.get(new Object[]{ "id" });
            if (idRow != null) {
                sslId = (String) idRow.get("Value");
            }

            CompositeData aliasRow = configProps.get(new Object[]{ "clientKeyAlias" });
            if (aliasRow != null) {
                clientAlias = (String) aliasRow.get("Value");
            }
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to read SSL config properties via JMX: " + e.getMessage());
            return;
        }

        if (sslId == null) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Could not determine SSL config id from JMX");
            return;
        }

        // --- Step 4: build SSLContext using the JMX-resolved id and alias ---
        SSLContext sslContext;
        try {
            Properties sslProps = JSSEHelper.getInstance().getProperties(sslId);
            sslProps.setProperty(Constants.SSLPROP_KEY_STORE_CLIENT_ALIAS, clientAlias);
            sslContext = JSSEHelper.getInstance().getSSLContext(null, sslProps);
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to build SSLContext for id='" + sslId + "' alias='" + clientAlias + "': " + e.getMessage());
            return;
        }

        // --- Step 5: make the outbound HTTPS call ---
        String responseBody;
        int statusCode;
        try {
            HttpsURLConnection conn = (HttpsURLConnection) URI.create(TARGET_URL).toURL().openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5_000);
            conn.setReadTimeout(10_000);
            statusCode = conn.getResponseCode();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                responseBody = reader.lines().collect(Collectors.joining("\n"));
            }
        } catch (IOException e) {
            response.sendError(HttpServletResponse.SC_BAD_GATEWAY,
                    "Outbound HTTPS call to '" + TARGET_URL + "' failed: " + e.getMessage());
            return;
        }

        // --- Step 6: write the result ---
        response.setContentType("text/plain;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        try (PrintWriter out = response.getWriter()) {
            out.printf("SSL config id (from JMX) : %s%n", sslId);
            out.printf("Cert alias    (from JMX) : %s%n", clientAlias);
            out.printf("Target URL               : %s%n", TARGET_URL);
            out.printf("HTTP status              : %d%n%n", statusCode);
            out.println("--- Response body ---");
            out.println(responseBody);
        }
    }
}
