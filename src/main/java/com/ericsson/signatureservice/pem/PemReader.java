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
package com.ericsson.signatureservice.pem;

import static java.util.Collections.disjoint;
import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toSet;

import static org.bouncycastle.openssl.PEMParser.TYPE_CERTIFICATE;
import static org.bouncycastle.openssl.PEMParser.TYPE_CMS;
import static org.bouncycastle.openssl.PEMParser.TYPE_PKCS7;
import static org.bouncycastle.openssl.PEMParser.TYPE_X509_CERTIFICATE;
import static org.bouncycastle.openssl.PEMParser.TYPE_X509_CRL;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;

import com.ericsson.signatureservice.exception.SignatureVerificationException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class PemReader {

    private static final Set<String> CMS_TYPES = Set.of(TYPE_CMS, TYPE_PKCS7);
    private static final Set<String> CERTIFICATE_TYPES = Set.of(TYPE_CERTIFICATE, TYPE_X509_CERTIFICATE);

    private final boolean ignoreCrlInfo;

    public PemReader(final boolean ignoreCrlInfo) {
        this.ignoreCrlInfo = ignoreCrlInfo;
    }

    public byte[] readCmsBytesFromPemString(final String pemString) {
        final List<PemObject> pemObjects = readPemObjectsFrom(pemString);

        validateTypes(pemObjects, CMS_TYPES);

        final List<byte[]> pemObjectsContent = getContentByObjectTypes(pemObjects, CMS_TYPES);

        if (pemObjectsContent.size() > 1) {
            throw new SignatureVerificationException("Provided PEM string contains more than one object of types " + sortedAndJoined(CMS_TYPES));
        }

        return pemObjectsContent.get(0);
    }

    public byte[] readCertificatesBytesFromPemString(final String pemString) {
        final List<PemObject> pemObjects = readPemObjectsFrom(pemString);

        validateTypes(pemObjects, CERTIFICATE_TYPES);

        final List<byte[]> pemObjectsContent = getContentByObjectTypes(pemObjects, CERTIFICATE_TYPES);

        return concatByteArrays(pemObjectsContent);
    }

    private static List<PemObject> readPemObjectsFrom(final String pemString) {
        try (Reader reader = new StringReader(pemString)) {
            final List<PemObject> pemObjects = new ArrayList<>();
            final PEMParser pemParser = new PEMParser(reader);

            PemObject pemObject = pemParser.readPemObject();
            while (pemObject != null) {
                pemObjects.add(pemObject);
                pemObject = pemParser.readPemObject();
            }

            return pemObjects;
        } catch (final IOException e) {
            throw new SignatureVerificationException("Could not read object(s) from PEM string", e);
        }
    }

    private void validateTypes(final List<PemObject> pemObjects, final Set<String> expectedTypes) {
        final Set<String> types = pemObjects.stream().map(PemObject::getType).collect(toSet());

        if (disjoint(types, expectedTypes)) {
            throw new SignatureVerificationException("Provided PEM string does not contain expected object types " + sortedAndJoined(expectedTypes));
        }

        if (types.contains(TYPE_X509_CRL)) {
            if (ignoreCrlInfo) {
                LOGGER.warn("PEM string contains CRL(s) which is not expected there");
            } else {
                throw new SignatureVerificationException("PEM string contains CRL(s) which is not expected there");
            }
        }

        final Set<String> remainingTypes = types.stream()
                .filter(type -> !expectedTypes.contains(type) && !Objects.equals(type, TYPE_X509_CRL))
                .collect(toSet());

        if (!remainingTypes.isEmpty()) {
            throw new SignatureVerificationException("PEM string contains unexpected object types " + sortedAndJoined(remainingTypes));
        }
    }

    private static String sortedAndJoined(final Set<String> types) {
        return types.stream().sorted().collect(joining(", "));
    }

    private static List<byte[]> getContentByObjectTypes(final List<PemObject> pemObjects, final Set<String> types) {
        return pemObjects.stream()
                .filter(pemObject -> types.contains(pemObject.getType()))
                .map(PemObject::getContent)
                .collect(Collectors.toList());
    }

    private static byte[] concatByteArrays(final List<byte[]> byteArrays) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream(totalSize(byteArrays))) {
            byteArrays.forEach(outputStream::writeBytes);

            return outputStream.toByteArray();
        } catch (final IOException e) {
            throw new RuntimeException("Could not concatenate byte arrays", e);
        }
    }

    private static int totalSize(final List<byte[]> byteArrays) {
        return byteArrays.stream().mapToInt(value -> value.length).sum();
    }
}
