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

/**
 * Servlet that prints the Liberty SSL configuration properties
 * using JSSEHelper 
 *
 */
@WebServlet("/sslinfo")
public class SSLInfoServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        Properties sslProps;
        try {
            JSSEHelper helper = JSSEHelper.getInstance();
            sslProps = helper.getProperties("defaultSSLConfig");
        } catch (Exception e) {
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
    }
}
