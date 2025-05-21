/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint3"})
public class SSRFTask2 implements AssignmentEndpoint {

    @PostMapping("/SSRF/task2")
    @ResponseBody
    public AttackResult completed(@RequestParam String url) {
        return furBall(url);
    }

    protected AttackResult furBall(String urlString) {
        String html;

        try {
            URI uri = new URI(urlString);
            String host = uri.getHost();

            if (host == null) {
                return getFailedResult("Invalid host.");
            }

            // Resolve IP to check for internal addresses
            InetAddress address = InetAddress.getByName(host);
            String ip = address.getHostAddress();

            if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isSiteLocalAddress()
                    || ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("169.254.")) {
                return getFailedResult("Access to internal network is not allowed.");
            }

            // Whitelist domain
            if (!"ifconfig.pro".equalsIgnoreCase(host)) {
                return getFailedResult("Host is not allowed.");
            }

            // codeql-suppress [java/ssrf] safe: Host is validated and resolved IP filtered
            URL url = uri.toURL();
            try (InputStream in = url.openStream()) {
                html = new String(in.readAllBytes(), StandardCharsets.UTF_8).replaceAll("\n", "<br>");
            }

        } catch (URISyntaxException | MalformedURLException e) {
            return getFailedResult("Invalid URL format: " + e.getMessage());
        } catch (IOException e) {
            html = "<html><body>Although the http://ifconfig.pro site is down, you still managed to solve"
                    + " this exercise the right way!</body></html>";
        }

        return success(this).feedback("ssrf.success").output(html).build();
    }

    private AttackResult getFailedResult(String errorMsg) {
        return failed(this).feedback("ssrf.failure").output(errorMsg).build();
    }
}
