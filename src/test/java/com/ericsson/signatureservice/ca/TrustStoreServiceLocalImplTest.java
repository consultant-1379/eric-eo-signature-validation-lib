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
package com.ericsson.signatureservice.ca;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;



import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.Test;

public class TrustStoreServiceLocalImplTest {

    @Test
    public void shouldReadCertificatesFromClasspathResource() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/trust-store-local-valid-ca/ca1.pem");

        // when and then
        assertThat(trustStoreService.getCertificatesBySubject("CN = Signing 1 CA")).isNotEmpty();
    }

    @Test
    public void shouldReadCertificatesFromFile() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("src/test/resources/signature/trust-store-local-valid-ca/ca1.pem");

        // when and then
        assertThat(trustStoreService.getCertificatesBySubject("CN = Signing 1 CA")).isNotEmpty();
    }

    @Test
    public void shouldReadCertificatesFromDirectory() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("src/test/resources/signature/trust-store-local-valid-ca");

        // when and then
        assertThat(trustStoreService.getCertificatesBySubject("CN = Signing 1 CA")).isNotEmpty();
    }

    @Test
    public void shouldReadCertificatesFromDirectoryWithNonPemAndInvalidCaFiles() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/trust-store-local-ca-directory-with-invalid-files");

        // when and then
        assertThat(trustStoreService.getCertificatesBySubject("CN = Signing 1 CA")).isNotEmpty();
    }

    @Test
    public void shouldTolerateInvalidCaFile() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/trust-store-local-ca-directory-with-invalid-files");

        // when and then
        assertThat(trustStoreService.getCertificatesBySubject("CN = Signing 1 CA")).isNotEmpty();
    }

    @Test
    public void shouldTolerateNonExistingPath() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("non-existing");

        // when and then
        assertThat(trustStoreService.getCertificatesBySubject("CN = Signing 1 CA")).isEmpty();
    }

    @Test
    public void shouldReturnCertificateByIssuerAndSerial() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/trust-store-local-valid-ca");

        // when
        final var certificate = trustStoreService.getCertificateBySelector(
                createCertSelector("CN = Intermediate 2 CA", "470675BF2E57DE3C3208EB40568F70DC1720CA49"));

        // then
        assertThat(certificate).isNotEmpty().containsInstanceOf(X509Certificate.class);
    }

    @Test
    public void shouldReturnEmptyByIssuerAndSerialWhenNotFound() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/trust-store-local-valid-ca");

        // when
        final var certificate = trustStoreService.getCertificateBySelector(
                createCertSelector("CN = Intermediate 5 CA", "4706"));

        // then
        assertThat(certificate).isEmpty();
    }

    @Test
    public void shouldReturnCertificatesBySubjectFromAllFiles() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/trust-store-local-valid-ca");

        // when
        final var certificatesFromCa1 = trustStoreService.getCertificatesBySubject("CN = Signing 1 CA");
        final var certificatesFromCa2 = trustStoreService.getCertificatesBySubject("CN = Root 3 CA");

        // then
        assertThat(certificatesFromCa1).hasSize(2).hasOnlyElementsOfType(X509Certificate.class);
        assertThat(certificatesFromCa2).hasSize(1).hasOnlyElementsOfType(X509Certificate.class);
    }

    @Test
    public void shouldReturnEmptyBySubjectWhenNotFound() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/trust-store-local-valid-ca");

        // when
        final var certificates = trustStoreService.getCertificatesBySubject("CN = Intermediate 3 CA");

        // then
        assertThat(certificates).isEmpty();
    }

    private static X509CertSelector createCertSelector(final String issuer, final String serial) {
        final var certSelector = new X509CertSelector();
        certSelector.setIssuer(new X500Principal(issuer));
        certSelector.setSerialNumber(new BigInteger(serial, 16));

        return certSelector;
    }
}
