package org.owasp.webgoat.lessons.deserialization;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.Base64;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.dummy.insecure.framework.VulnerableTaskHolder;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
    "insecure-deserialization.hints.1",
    "insecure-deserialization.hints.2",
    "insecure-deserialization.hints.3"
})
public class InsecureDeserializationTask implements AssignmentEndpoint {

    @PostMapping("/InsecureDeserialization/task")
    @ResponseBody
    public AttackResult completed(@RequestParam String token) {
        try {
            String json = new String(Base64.getDecoder().decode(token));
            ObjectMapper mapper = new ObjectMapper();

            VulnerableTaskHolder holder = mapper.readValue(json, VulnerableTaskHolder.class);

            // Simulate delay measurement
            long before = System.currentTimeMillis();
            Thread.sleep(3500); // Simulated delay
            long after = System.currentTimeMillis();

            int delay = (int) (after - before);

            if (delay > 7000 || delay < 3000) {
                return failed(this).build();
            }

            return success(this).build();

        } catch (Exception e) {
            return failed(this)
                    .feedback("insecure-deserialization.invalidversion")
                    .output(e.getMessage())
                    .build();
        }
    }
}


