/*
 * COPYRIGHT Ericsson 2024
 *
 *
 *
 * The copyright to the computer program(s) herein is the property of
 *
 * Ericsson Inc. The programs may be used and/or copied only with written
 *
 * permission from Ericsson Inc. or in accordance with the terms and
 *
 * conditions stipulated in the agreement/contract under which the
 *
 * program(s) have been supplied.
 */
package com.ericsson.signatureservice.test;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class TestUtil {

    public static String readFile(final String path) {
        try {
            return Files.readString(Paths.get(getClasspathUrl(path).toURI()));
        } catch (IOException | URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static InputStream openInputStream(final String path) {
        try {
            return getClasspathUrl(path).openStream();
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static URL getClasspathUrl(final String path) {
        final var url = TestUtil.class.getClassLoader().getResource(path);
        if (url == null) {
            throw new IllegalArgumentException(String.format("Resource %s could not be found", path));
        }

        return url;
    }
}
