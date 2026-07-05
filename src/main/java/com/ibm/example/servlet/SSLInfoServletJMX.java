package com.ibm.example.servlet;

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
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.util.Properties;
import java.util.Set;

/**
 * Servlet that prints Liberty SSL configuration properties.
 *
 * The SSL config id is resolved exclusively via JMX:
 *   - Queries the OSGi ConfigurationAdminMBean for all entries with
 *     factory PID com.ibm.ws.ssl.repertoire (Liberty's <ssl> elements)
 *   - Reads the "id" attribute from each entry and prints its properties
 */
@WebServlet("/sslinfojmx")
public class SSLInfoServletJMX extends HttpServlet {

    /** Liberty OSGi ConfigurationAdminMBean object name pattern */
    private static final String CONFIG_ADMIN_OBJECT_NAME = "osgi.compendium:service=cm,version=1.3,*";

    /** Liberty internal factory PID for <ssl> configuration elements */
    private static final String SSL_FACTORY_PID = "com.ibm.ws.ssl.repertoire";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Step 1: locate the ConfigurationAdminMBean
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

        // Step 2: query all <ssl> config entries by factory PID
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

        response.setContentType("text/plain;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");

        try (PrintWriter out = response.getWriter()) {
            out.printf("Found %d SSL configuration(s) via JMX%n%n", sslConfigs.length);

            // Step 3: for each SSL config entry, read id + fetch SSL properties
            for (String[] entry : sslConfigs) {
                String pid = entry[0];

                // Read the server.xml id attribute from the OSGi config properties
                String sslId = null;
                try {
                    TabularData configProps = (TabularData) mbs.invoke(
                            configAdminMBean,
                            "getProperties",
                            new Object[]{ pid },
                            new String[]{ String.class.getName() });

                    CompositeData idRow = configProps.get(new Object[]{ "id" });
                    if (idRow != null) {
                        sslId = (String) idRow.get("Value");
                    }
                } catch (Exception e) {
                    out.printf("  [pid=%s] Failed to read JMX properties: %s%n%n", pid, e.getMessage());
                    continue;
                }

                out.printf("=== SSL Config id: %s  (OSGi pid: %s) ===%n", sslId, pid);

                if (sslId == null) {
                    out.println("  id attribute not found in JMX config properties");
                    out.println();
                    continue;
                }

                // Step 4: use the id to fetch the full SSL properties via JSSEHelper
                try {
                    Properties sslProps = JSSEHelper.getInstance().getProperties(sslId);
                    sslProps.forEach((k, v) -> out.printf("  %-42s = %s%n", k, v));
                } catch (Exception e) {
                    out.printf("  Failed to retrieve SSL properties for id '%s': %s%n", sslId, e.getMessage());
                }
                out.println();
            }
        }
    }
}
