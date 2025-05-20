package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.StringReader;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.*;
import org.xml.sax.InputSource;

@RestController
@AssignmentHints({"vulnerable.hint"})
public class VulnerableComponentsLesson implements AssignmentEndpoint {

    @PostMapping("/VulnerableComponents/attack1")
    public @ResponseBody AttackResult completed(@RequestParam String payload) {
        try {
            if (payload == null || payload.trim().isEmpty()) {
                return failed(this)
                        .feedback("vulnerable-components.invalid-payload")
                        .build();
            }

            // Secure XML parser configuration to prevent XXE attacks
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setExpandEntityReferences(false);
            factory.setNamespaceAware(true);
            factory.setXIncludeAware(false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            InputSource inputSource = new InputSource(new StringReader(payload));
            Document doc = builder.parse(inputSource);

            Element root = doc.getDocumentElement();
            if (root == null || !"contact".equals(root.getTagName())) {
                return failed(this)
                        .feedback("vulnerable-components.invalid-root-element")
                        .build();
            }

            String firstName = getElementText(root, "firstName");
            String lastName = getElementText(root, "lastName");
            String email = getElementText(root, "email");

            // Manually populate ContactImpl (safe, not deserialized)
            ContactImpl contact = new ContactImpl();
            contact.setFirstName(firstName);
            contact.setLastName(lastName);
            contact.setEmail(email);

            // Example usage
            contact.getFirstName();

            return success(this)
                    .feedback("vulnerable-components.success")
                    .build();

        } catch (Exception e) {
            return failed(this)
                    .feedback("vulnerable-components.close")
                    .output("XML parsing failed: " + e.getMessage())
                    .build();
        }
    }

    // Helper to safely extract text from XML element
    private String getElementText(Element parent, String tagName) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() > 0 && nodes.item(0).getFirstChild() != null) {
            return nodes.item(0).getFirstChild().getNodeValue();
        }
        return null;
    }
}

