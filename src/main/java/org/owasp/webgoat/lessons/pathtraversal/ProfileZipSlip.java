/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.http.MediaType.ALL_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@AssignmentHints({
  "path-traversal-zip-slip.hint1",
  "path-traversal-zip-slip.hint2",
  "path-traversal-zip-slip.hint3",
  "path-traversal-zip-slip.hint4"
})
@Slf4j
public class ProfileZipSlip extends ProfileUploadBase {

  public ProfileZipSlip(@Value("${webgoat.server.directory}") String webGoatHomeDirectory) {
    super(webGoatHomeDirectory);
  }

  @PostMapping(
      value = "/PathTraversal/zip-slip",
      consumes = ALL_VALUE,
      produces = APPLICATION_JSON_VALUE)
  @ResponseBody
  public AttackResult uploadFileHandler(
      @RequestParam("uploadedFileZipSlip") MultipartFile file, @CurrentUsername String username) {
    if (!file.getOriginalFilename().toLowerCase().endsWith(".zip")) {
      return failed(this).feedback("path-traversal-zip-slip.no-zip").build();
    } else {
      return processZipUpload(file, username);
    }
  }

  @SneakyThrows
private AttackResult processZipUpload(MultipartFile file, String username) {
    var tmpZipDirectory = Files.createTempDirectory(username);
    var safeExtractDirectory = cleanupAndCreateDirectoryForUser(username).toPath().toAbsolutePath().normalize();
    var currentImage = getProfilePictureAsBase64(username);

    try {
        var uploadedZipFile = tmpZipDirectory.resolve(file.getOriginalFilename());
        FileCopyUtils.copy(file.getBytes(), uploadedZipFile.toFile());

        try (ZipFile zip = new ZipFile(uploadedZipFile.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();

                // Προετοιμασία του path προορισμού με εξομάλυνση (normalize)
                File destinationFile = new File(safeExtractDirectory.toFile(), entry.getName());
                Path normalizedDestinationPath = destinationFile.toPath().normalize();

                // ΕΛΕΓΧΟΣ: να μην επιτρέπεται εξαγωγή εκτός του επιτρεπόμενου καταλόγου
                if (!normalizedDestinationPath.startsWith(safeExtractDirectory)) {
                    log.warn("Blocked Zip Slip attempt: {}", entry.getName());
                    continue;
                }

                if (entry.isDirectory()) {
                    Files.createDirectories(normalizedDestinationPath);
                } else {
                    Files.createDirectories(normalizedDestinationPath.getParent());
                    try (InputStream is = zip.getInputStream(entry)) {
                        Files.copy(is, normalizedDestinationPath, StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            }
        }

        return isSolved(currentImage, getProfilePictureAsBase64(username));
    } catch (IOException e) {
        return failed(this).output(e.getMessage()).build();
    }
}

