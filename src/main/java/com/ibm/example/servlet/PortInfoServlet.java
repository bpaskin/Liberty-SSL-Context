package com.ibm.example.servlet;

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
import java.util.Set;
import java.util.logging.Logger;

/**
 * Servlet that reports the HTTP and HTTPS port numbers configured in Liberty.
 *
 * Resolution strategy (two sources, both shown):
 *
 *   Source A — WebSphere:feature=channelfw,type=endpoint,* MBeans
 *     Liberty registers one MBean per active channel endpoint:
 *       - Plain HTTP  → name = "<id>"      (e.g. "defaultHttpEndpoint")
 *       - HTTPS/TLS   → name = "<id>-ssl"  (e.g. "defaultHttpEndpoint-ssl")
 *     Each exposes: Name (String), Port (int), Host (String).
 *
 *   Source B — OSGi ConfigurationAdminMBean (factory PID com.ibm.ws.http)
 *     Reads <httpEndpoint> config entries directly from OSGi and extracts
 *     id, httpPort, httpsPort, and host.
 *
 * Maps to /portinfo.
 */
@WebServlet("/portinfo")
public class PortInfoServlet extends HttpServlet {

    private static final Logger LOG = Logger.getLogger(PortInfoServlet.class.getName());

    /** Matches both plain and SSL channel endpoint MBeans */
    private static final String CHANNEL_ENDPOINT_PATTERN = "WebSphere:feature=channelfw,type=endpoint,*";

    /** Liberty OSGi ConfigurationAdminMBean object name pattern */
    private static final String CONFIG_ADMIN_OBJECT_NAME = "osgi.compendium:service=cm,version=1.3,*";

    /** OSGi factory PID for Liberty <httpEndpoint> elements */
    private static final String HTTP_ENDPOINT_FACTORY_PID = "com.ibm.ws.http";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        LOG.fine("doGet invoked");

        MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();

        response.setContentType("text/html;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");

        try (PrintWriter out = response.getWriter()) {
            out.println("<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>");
            out.println("<title>Liberty Port Info</title><style>");
            out.println("body{font-family:-apple-system,'Segoe UI',system-ui,sans-serif;"
                    + "font-size:14px;line-height:1.6;max-width:820px;margin:40px auto;"
                    + "padding:0 20px;color:#1f2328}");
            out.println("h1{font-size:1.3em;border-bottom:1px solid #e5e7eb;padding-bottom:6px}");
            out.println("h2{font-size:1.05em;margin-top:28px;color:#3b82d4}");
            out.println("table{border-collapse:collapse;width:100%;margin-bottom:16px}");
            out.println("th,td{border:1px solid #e5e7eb;padding:6px 10px;text-align:left}");
            out.println("th{background:#f7f8fa}");
            out.println(".none{color:#57606a;font-style:italic}");
            out.println(".err{color:#cf222e}");
            out.println("</style></head><body>");
            out.println("<h1>Liberty HTTP / HTTPS Port Information</h1>");

            // ----------------------------------------------------------------
            // Source A: channel endpoint MBeans
            // ----------------------------------------------------------------
            out.println("<h2>Source A — Channel endpoint MBeans"
                    + " (<code>" + CHANNEL_ENDPOINT_PATTERN + "</code>)</h2>");
            try {
                Set<ObjectName> names = mbs.queryNames(new ObjectName(CHANNEL_ENDPOINT_PATTERN), null);
                LOG.fine("Channel endpoint MBeans found: " + names.size());
                if (names.isEmpty()) {
                    out.println("<p class='none'>No channel endpoint MBeans found — "
                            + "is <code>monitor-1.0</code> enabled?</p>");
                } else {
                    out.println("<table><tr><th>Name</th><th>Port</th><th>Host</th><th>Type</th></tr>");
                    for (ObjectName on : names) {
                        String epName = attrStr(mbs, on, "Name");
                        String port   = attrStr(mbs, on, "Port");
                        String host   = attrStr(mbs, on, "Host");
                        String type   = epName != null && epName.endsWith("-ssl") ? "HTTPS" : "HTTP";
                        out.printf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>%n",
                                escHtml(epName != null ? epName : "(unknown)"),
                                escHtml(port   != null ? port   : "(unknown)"),
                                escHtml(host   != null ? host   : "(unknown)"),
                                type);
                    }
                    out.println("</table>");
                }
            } catch (Exception e) {
                LOG.warning("Source A failed: " + e.getMessage());
                out.printf("<p class='err'>Failed to query channel endpoint MBeans: %s: %s</p>%n",
                        escHtml(e.getClass().getSimpleName()), escHtml(e.getMessage()));
            }

            // ----------------------------------------------------------------
            // Source B: OSGi ConfigurationAdminMBean
            // ----------------------------------------------------------------
            out.println("<h2>Source B — OSGi ConfigurationAdminMBean"
                    + " (<code>" + HTTP_ENDPOINT_FACTORY_PID + "</code>)</h2>");

            ObjectName configAdminMBean = null;
            try {
                Set<ObjectName> names = mbs.queryNames(new ObjectName(CONFIG_ADMIN_OBJECT_NAME), null);
                if (names.isEmpty()) {
                    out.println("<p class='err'>OSGi ConfigurationAdminMBean not found — "
                            + "is <code>monitor-1.0</code> enabled?</p>");
                } else {
                    configAdminMBean = names.iterator().next();
                    LOG.fine("Using ConfigurationAdminMBean: " + configAdminMBean);
                }
            } catch (Exception e) {
                LOG.warning("ConfigurationAdminMBean lookup failed: " + e.getMessage());
                out.printf("<p class='err'>Failed to locate ConfigurationAdminMBean: %s: %s</p>%n",
                        escHtml(e.getClass().getSimpleName()), escHtml(e.getMessage()));
            }

            if (configAdminMBean != null) {
                String[][] epConfigs = null;
                try {
                    epConfigs = (String[][]) mbs.invoke(
                            configAdminMBean,
                            "getConfigurations",
                            new Object[]{ "(service.factoryPid=" + HTTP_ENDPOINT_FACTORY_PID + ")" },
                            new String[]{ String.class.getName() });
                    LOG.fine("OSGi http endpoint entries: " + (epConfigs == null ? 0 : epConfigs.length));
                } catch (Exception e) {
                    LOG.warning("getConfigurations failed: " + e.getMessage());
                    out.printf("<p class='err'>getConfigurations failed: %s: %s</p>%n",
                            escHtml(e.getClass().getSimpleName()), escHtml(e.getMessage()));
                }

                if (epConfigs == null || epConfigs.length == 0) {
                    out.printf("<p class='none'>No entries found for factory PID"
                            + " <code>%s</code>.</p>%n", escHtml(HTTP_ENDPOINT_FACTORY_PID));
                } else {
                    out.println("<table><tr><th>id</th><th>httpPort</th>"
                            + "<th>httpsPort</th><th>host</th><th>OSGi pid token</th></tr>");
                    for (String[] entry : epConfigs) {
                        String pid = entry[0];
                        try {
                            TabularData props = (TabularData) mbs.invoke(
                                    configAdminMBean, "getProperties",
                                    new Object[]{ pid }, new String[]{ String.class.getName() });
                            String id        = stringProp(props, "id");
                            String httpPort  = stringProp(props, "httpPort");
                            String httpsPort = stringProp(props, "httpsPort");
                            String host      = stringProp(props, "host");
                            out.printf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>%n",
                                    escHtml(id        != null ? id        : "(none)"),
                                    escHtml(httpPort  != null ? httpPort  : "(none)"),
                                    escHtml(httpsPort != null ? httpsPort : "(none)"),
                                    escHtml(host      != null ? host      : "(none)"),
                                    escHtml(pid));
                        } catch (Exception e) {
                            LOG.warning("Failed to read OSGi props for pid=" + pid + ": " + e.getMessage());
                            out.printf("<tr><td colspan='5' class='err'>pid=%s — %s: %s</td></tr>%n",
                                    escHtml(pid), escHtml(e.getClass().getSimpleName()),
                                    escHtml(e.getMessage()));
                        }
                    }
                    out.println("</table>");
                }
            }

            out.println("<hr style='margin-top:40px;border:none;border-top:1px solid #e5e7eb'>");
            out.println("</body></html>");
        }

        LOG.fine("doGet completed");
    }

    // -----------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------

    /** Reads an MBean attribute as a String; returns null on any error. */
    private static String attrStr(MBeanServer mbs, ObjectName on, String attr) {
        try {
            Object v = mbs.getAttribute(on, attr);
            return v == null ? null : String.valueOf(v);
        } catch (Exception e) {
            LOG.fine("Could not read attribute '" + attr + "' from " + on + ": " + e.getMessage());
            return null;
        }
    }

    /** Extracts a named property value from a ConfigurationAdmin TabularData. */
    private static String stringProp(TabularData props, String key) {
        if (props == null) return null;
        CompositeData row = props.get(new Object[]{ key });
        if (row == null) return null;
        Object val = row.get("Value");
        return val == null ? null : String.valueOf(val);
    }

    /** Minimal HTML escaping. */
    private static String escHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
