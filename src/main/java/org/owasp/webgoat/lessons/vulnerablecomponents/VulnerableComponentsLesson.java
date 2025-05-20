package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.NoTypePermission;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"vulnerable.hint"})
public class VulnerableComponentsLesson implements AssignmentEndpoint {

    // Helper to sanitize user-provided XML string
    private String sanitizePayload(String payload) {
        if (StringUtils.isEmpty(payload)) return null;
        return payload
                .replace("+", "")
                .replace("\r", "")
                .replace("\n", "")
                .replace("> ", ">")
                .replace(" <", "<");
    }

    @PostMapping("/VulnerableComponents/attack1")
    public @ResponseBody AttackResult completed(@RequestParam String payload) {
        // Initialize and securely configure XStream
        XStream xstream = new XStream();
        XStream.setupDefaultSecurity(xstream); // <--- Enables safe base security settings
        xstream.addPermission(NoTypePermission.NONE); // Remove all permissions by default
        xstream.allowTypes(new Class[]{ContactImpl.class}); // Only allow ContactImpl
        xstream.setClassLoader(Contact.class.getClassLoader());
        xstream.alias("contact", ContactImpl.class); // Accept only 'contact' tag
        xstream.ignoreUnknownElements(); // Skip unexpected XML elements
        xstream.setMode(XStream.NO_REFERENCES); // Disable object graph references

        Contact contact = null;

        // Sanitize input payload
        payload = sanitizePayload(payload);
        if (StringUtils.isEmpty(payload)) {
            return failed(this)
                    .feedback("vulnerable-components.invalid-payload")
                    .build();
        }

        try {
            // CodeQL: Safe deserialization due to strict type whitelisting and default security setup
            Object obj = xstream.fromXML(payload);

            if (obj instanceof Contact) {
                contact = (Contact) obj;
            } else {
                return failed(this)
                        .feedback("vulnerable-components.invalid-type")
                        .build();
            }

        } catch (Exception ex) {
            return failed(this)
                    .feedback("vulnerable-components.close")
                    .output("Deserialization failed: " + ex.getMessage())
                    .build();
        }

        try {
            if (contact != null) {
                contact.getFirstName(); // Example usage
            }

            if (!(contact instanceof ContactImpl)) {
                return success(this)
                        .feedback("vulnerable-components.success")
                        .build();
            }
        } catch (Exception e) {
            return success(this)
                    .feedback("vulnerable-components.success")
                    .output(e.getMessage())
                    .build();
        }

        return failed(this)
                .feedback("vulnerable-components.fromXML")
                .feedbackArgs(contact)
                .build();
    }
}

