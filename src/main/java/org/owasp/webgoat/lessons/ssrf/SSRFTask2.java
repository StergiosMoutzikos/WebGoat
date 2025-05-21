package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.regex.Pattern;

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

    private static final Set<String> ALLOWED_HOSTS = Set.of("ifconfig.pro");
    private static final Pattern IP_PRIVATE_PATTERN = Pattern.compile(
            "^(127\\.\\d+\\.\\d+\\.\\d+)|(10\\.)|(192\\.168\\.)|(172\\.(1[6-9]|2\\d|3[0-1])\\.).*");

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

            // 🔐 Reject local IPs
            if (host == null || IP_PRIVATE_PATTERN.matcher(host).matches() || host.equalsIgnoreCase("localhost")) {
                return getFailedResult("Access to internal IPs is not allowed.");
            }

            // ✅ Allow only exact match for safe domain
            if (!ALLOWED_HOSTS.contains(host)) {
                return getFailedResult("Host is not allowed.");
            }

            URL url = uri.toURL();
            try (InputStream in = url.openStream()) {
                html = new String(in.readAllBytes(), StandardCharsets.UTF_8).replaceAll("\n", "<br>");
            }

        } catch (MalformedURLException | URISyntaxException e) {
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
