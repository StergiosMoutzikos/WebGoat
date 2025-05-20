package org.owasp.webgoat.lessons.deserialization;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Base64;

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
    public AttackResult completed(@RequestParam String token) throws IOException {
        String b64token;
        long before;
        long after;
        int delay;

        b64token = token.replace('-', '+').replace('_', '/');

        try (WhitelistedObjectInputStream ois = new WhitelistedObjectInputStream(
                new ByteArrayInputStream(Base64.getDecoder().decode(b64token)))) {
            before = System.currentTimeMillis();
            Object o = ois.readObject();
            after = System.currentTimeMillis();

            if (!(o instanceof VulnerableTaskHolder)) {
                if (o instanceof String) {
                    return failed(this).feedback("insecure-deserialization.stringobject").build();
                }
                return failed(this).feedback("insecure-deserialization.wrongobject").build();
            }

        } catch (InvalidClassException e) {
            return failed(this).feedback("insecure-deserialization.invalidversion").build();
        } catch (IllegalArgumentException e) {
            return failed(this).feedback("insecure-deserialization.expired").build();
        } catch (Exception e) {
            return failed(this).feedback("insecure-deserialization.invalidversion").build();
        }

        delay = (int) (after - before);
        if (delay > 7000 || delay < 3000) {
            return failed(this).build();
        }

        return success(this).build();
    }

    /**
     * Custom ObjectInputStream that only allows deserialization of whitelisted classes.
     */
    static class WhitelistedObjectInputStream extends ObjectInputStream {
        public WhitelistedObjectInputStream(ByteArrayInputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            String className = desc.getName();
            // Only allow specific class to be deserialized
            if (!"org.dummy.insecure.framework.VulnerableTaskHolder".equals(className)) {
                throw new InvalidClassException("Unauthorized deserialization attempt: " + className);
            }
            return super.resolveClass(desc);
        }
    }
}

