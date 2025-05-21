package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;

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

    // Whitelist of approved targets
    private static final Map<String, String> WHITELISTED_TARGETS = Map.of(
            "ifconfig", "http://ifconfig.pro"
    );

    @PostMapping("/SSRF/task2")
    @ResponseBody
    public AttackResult completed(@RequestParam String targetKey) {
        return fetchFromWhitelistedTarget(targetKey);
    }

    protected AttackResult fetchFromWhitelistedTarget(String key) {
        String urlString = WHITELISTED_TARGETS.get(key);
        if (urlString == null) {
            String html = "<img class=\"image\" alt=\"image post\" src=\"images/cat.jpg\">";
            return getFailedResult(html);
        }

        String html;
        try (InputStream in = new URL(urlString).openStream()) {
            html = new String(in.readAllBytes(), StandardCharsets.UTF_8).replaceAll("\n", "<br>");
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
