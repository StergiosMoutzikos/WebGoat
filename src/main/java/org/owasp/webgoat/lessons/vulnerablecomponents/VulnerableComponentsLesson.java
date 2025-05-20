// Updated
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

  @PostMapping("/VulnerableComponents/attack1")
  public @ResponseBody AttackResult completed(@RequestParam String payload) {
    XStream xstream = new XStream();

    // **SECURE: Remove all default permissions**
    xstream.addPermission(NoTypePermission.NONE);

    // **Allow only ContactImpl class to be deserialized**
    xstream.allowTypes(new Class[]{ContactImpl.class});

    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    
    Contact contact = null;

    try {
      if (!StringUtils.isEmpty(payload)) {
        payload =
            payload
                .replace("+", "")
                .replace("\r", "")
                .replace("\n", "")
                .replace("> ", ">")
                .replace(" <", "<");
      }
      // Safely deserialize, restricted to allowed types only
      try {
    if (!StringUtils.isEmpty(payload)) {
        payload =
            payload
                .replace("+", "")
                .replace("\r", "")
                .replace("\n", "")
                .replace("> ", ">")
                .replace(" <", "<");
    }
    // Try to deserialize only if payload is not empty
    if (!StringUtils.isEmpty(payload)) {
        Object obj = xstream.fromXML(payload);

        if (obj instanceof Contact) {
            contact = (Contact) obj;
        } else {
            // Not a Contact object, handle appropriately
            return failed(this)
                .feedback("vulnerable-components.invalid-type")
                .build();
        }
    }
} catch (Exception ex) {
    return failed(this)
        .feedback("vulnerable-components.close")
        .output(ex.getMessage())
        .build();
}

    } catch (Exception ex) {
      return failed(this)
          .feedback("vulnerable-components.close")
          .output(ex.getMessage())
          .build();
    }

    try {
      if (null != contact) {
        contact.getFirstName(); // trigger example
      }
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
