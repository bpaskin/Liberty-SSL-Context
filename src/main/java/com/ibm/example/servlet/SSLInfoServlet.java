package com.ibm.example.servlet;

import com.ibm.websphere.ssl.JSSEHelper;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * Servlet that prints the Liberty SSL configuration properties
 * using JSSEHelper 
 *
 */
@WebServlet("/sslinfo")
public class SSLInfoServlet extends HttpServlet {

    private static final Logger LOG = Logger.getLogger(SSLInfoServlet.class.getName());

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        LOG.fine("doGet invoked");

        LOG.fine("Fetching SSL properties via JSSEHelper for id='defaultSSLConfig'");
        Properties sslProps;
        try {
            JSSEHelper helper = JSSEHelper.getInstance();
            sslProps = helper.getProperties("defaultSSLConfig");
            LOG.fine("Retrieved " + sslProps.size() + " SSL properties");
        } catch (Exception e) {
            LOG.warning("Failed to retrieve SSL properties: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to retrieve SSL properties: " + e.getMessage());
            return;
        }

        response.setContentType("text/plain;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");

        try (PrintWriter out = response.getWriter()) {
            out.println("--- SSL Properties ---");
            sslProps.forEach((k, v) -> out.printf("%-42s = %s%n", k, v));
        }
        LOG.fine("doGet completed");
    }
}
