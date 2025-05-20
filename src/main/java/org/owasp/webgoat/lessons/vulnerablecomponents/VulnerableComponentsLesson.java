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

    // Utility method to sanitize the payload
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
        // Initialize and configure XStream securely
        XStream xstream = new XStream();
        xstream.addPermission(NoTypePermission.NONE); // Remove all permissions
        xstream.allowTypes(new Class[]{ContactImpl.class}); // Allow only ContactImpl
        xstream.setClassLoader(Contact.class.getClassLoader());
        xstream.alias("contact", ContactImpl.class);
        xstream.ignoreUnknownElements();
        xstream.setMode(XStream.NO_REFERENCES); // Optional: Disable references

        Contact contact = null;

        // Sanitize the input
        payload = sanitizePayload(payload);
        if (StringUtils.isEmpty(payload)) {
            return failed(this)
                    .feedback("vulnerable-components.invalid-payload")
                    .build();
        }

        try {
            // Attempt safe deserialization
            Object obj = xstream.fromXML(payload);

            // Verify object type
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

        // Attempt to use the deserialized object
        try {
            if (contact != null) {
                contact.getFirstName(); // Simulated logic use
            }
            // Validate that the object is the correct implementation
            if (!(contact instanceof ContactImpl)) {
                return success(this).feedback("vulnerable-components.success").build();
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
