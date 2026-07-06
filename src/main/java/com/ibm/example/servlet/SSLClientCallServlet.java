package com.ibm.example.servlet;

import com.ibm.websphere.ssl.Constants;
import com.ibm.websphere.ssl.JSSEHelper;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.stream.Collectors;

/**
 * Servlet that makes an outbound HTTPS call using a specific client certificate
 * alias selected via JSSEHelper.
 *
 * Change TARGET_URL and CLIENT_CERT_ALIAS to match your environment.
 */
@WebServlet("/sslcall")
public class SSLClientCallServlet extends HttpServlet {

    /** Target HTTPS endpoint to call. */
    private static final String TARGET_URL = "https://ibm.com";

    /** Alias of the client certificate to present during the TLS handshake. */
    private static final String CLIENT_CERT_ALIAS = "clientCert";

    /** Liberty SSL configuration id from server.xml. */
    private static final String SSL_CONFIG_ID = "defaultSSLConfig";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // --- Build an SSLContext with the chosen client cert alias ---
        SSLContext sslContext;
        try {
            JSSEHelper helper = JSSEHelper.getInstance();
            Properties sslProps = helper.getProperties(SSL_CONFIG_ID);
            sslProps.setProperty(Constants.SSLPROP_KEY_STORE_CLIENT_ALIAS, CLIENT_CERT_ALIAS);
            sslContext = helper.getSSLContext(null, sslProps);
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to build SSLContext for alias '" + CLIENT_CERT_ALIAS + "': " + e.getMessage());
            return;
        }

        // --- Make the outbound HTTPS call ---
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

        // --- Return the result ---
        response.setContentType("text/plain;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        try (PrintWriter out = response.getWriter()) {
            out.printf("Target URL  : %s%n", TARGET_URL);
            out.printf("Cert alias  : %s%n", CLIENT_CERT_ALIAS);
            out.printf("HTTP status : %d%n%n", statusCode);
            out.println("--- Response body ---");
            out.println(responseBody);
        }
    }
}
