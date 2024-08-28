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
package com.ericsson.signatureservice;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import static com.ericsson.signatureservice.test.TestUtil.openInputStream;
import static com.ericsson.signatureservice.test.TestUtil.readFile;

import org.junit.jupiter.api.Test;

import com.ericsson.signatureservice.ca.TrustStoreServiceLocalImpl;
import com.ericsson.signatureservice.exception.SignatureVerificationException;
import com.ericsson.signatureservice.test.TrustStoreServiceNoOpImpl;

public class SignatureServiceImplTest {

    @Test
    public void shouldSucceedVerificationWithThreeSignersInDifferentLocationsAndValidCertificateChain() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/multiple-signers-success/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/multiple-signers-success/data.txt");
        final var signature = readFile("signature/multiple-signers-success/signature.cms");
        final var certificate = readFile("signature/multiple-signers-success/certificate.pem");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature, certificate));
    }

    @Test
    public void shouldSucceedVerificationWithTwoSignersInDifferentLocationsAndSeparateValidCertificateChains() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/two-separate-chains-success/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/two-separate-chains-success/data.txt");
        final var signature = readFile("signature/two-separate-chains-success/signature.cms");
        final var certificate = readFile("signature/two-separate-chains-success/certificate.pem");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature, certificate));
    }

    @Test
    public void shouldSucceedVerificationWithSigningCertificateInSignatureSignedByRootCa() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/root-ca-signed-signing-cert-in-signature-success/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/root-ca-signed-signing-cert-in-signature-success/data.txt");
        final var signature = readFile("signature/root-ca-signed-signing-cert-in-signature-success/signature.cms");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature));
    }

    @Test
    public void shouldSucceedVerificationWithSigningCertificateExternalSignedByRootCa() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/root-ca-signed-signing-cert-external-success/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/root-ca-signed-signing-cert-external-success/data.txt");
        final var signature = readFile("signature/root-ca-signed-signing-cert-external-success/signature.cms");
        final var certificate = readFile("signature/root-ca-signed-signing-cert-external-success/certificate.pem");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature, certificate));
    }

    @Test
    public void shouldSucceedVerificationWithContentSignedByRootCa() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/root-ca-signed-content-success/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/root-ca-signed-content-success/data.txt");
        final var signature = readFile("signature/root-ca-signed-content-success/signature.cms");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature));
    }

    @Test
    public void shouldSucceedVerificationWithEmbeddedAndRootCaSigningCertificatesByComplexIssuer() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signature-with-complex-issuer-success/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/signature-with-complex-issuer-success/data.txt");
        final var signature = readFile("signature/signature-with-complex-issuer-success/signature.cms");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature));
    }

    @Test
    public void shouldSucceedVerificationWithEmbeddedAndRootCaSigningCertificatesBySubjectKeyIdentifier() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signature-with-subject-key-identifier-success/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/signature-with-subject-key-identifier-success/data.txt");
        final var signature = readFile("signature/signature-with-subject-key-identifier-success/signature.cms");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature));
    }

    @Test
    public void shouldFailVerificationWithSelfSignedSigningCertificate() {
        // given
        final var signatureService = new SignatureServiceImpl(new TrustStoreServiceNoOpImpl(), false, false);

        final var contentStream = openInputStream("signature/self-signed-signing-cert-failure/data.txt");
        final var signature = readFile("signature/self-signed-signing-cert-failure/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Could not find valid trusted certificate for signature "
                                    + "[Certificate issuer: CN=Self-signed signing, serial number: 1627975A3DEA719D4F43E8FC9290F0836353E53A]");
    }

    @Test
    public void shouldFailVerificationWithSelfSignedVendorCertificate() {
        // given
        final var signatureService = new SignatureServiceImpl(new TrustStoreServiceNoOpImpl(), false, false);

        final var contentStream = openInputStream("signature/self-signed-vendor-intermediate-cert-failure/data.txt");
        final var signature = readFile("signature/self-signed-vendor-intermediate-cert-failure/signature.cms");
        final var certificate = readFile("signature/self-signed-vendor-intermediate-cert-failure/certificate.pem");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature, certificate))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Could not find valid trusted certificate for signature "
                                    + "[Certificate issuer: CN=Self-signed signing, serial number: 36C7FAEDCB985BC0B4221AFC2E44C60137C14089]");
    }

    @Test
    public void shouldFailVerificationWithIncompleteVendorCertificateChain() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/incomplete-chain-failure/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/incomplete-chain-failure/data.txt");
        final var signature = readFile("signature/incomplete-chain-failure/signature.cms");
        final var certificate = readFile("signature/incomplete-chain-failure/certificate.pem");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature, certificate))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Could not find valid trusted certificate for signature "
                                    + "[Certificate issuer: CN=Intermediate 2 embedded, serial number: E0D83C938B9753BE2C1122D884B63E9CA74E945]");
    }

    @Test
    public void shouldFailVerificationWithTwoSignersAndSecondIsNotTrusted() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/two-signers-second-not-trusted-failure/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/two-signers-second-not-trusted-failure/data.txt");
        final var signature = readFile("signature/two-signers-second-not-trusted-failure/signature.cms");
        final var certificate = readFile("signature/two-signers-second-not-trusted-failure/certificate.pem");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature, certificate))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Could not find valid trusted certificate for signature "
                                    + "[Certificate issuer: CN=Root 2 CA, serial number: 7827F96E83D52E41A25C2020D2BCE6E681D7D7B4]");
    }

    @Test
    public void shouldFailVerificationWithContentNotMatchingSignature() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/content-not-matching-signature-failure/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/content-not-matching-signature-failure/data.txt");
        final var signature = readFile("signature/content-not-matching-signature-failure/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Content's signature [Certificate issuer: CN=Self-signed signing, "
                                    + "serial number: 1627975A3DEA719D4F43E8FC9290F0836353E53A] failed verification");
    }

    @Test
    public void shouldSucceedVerificationWithVendorCertificateWithoutKeyUsage() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signing-vendor-certificate-without-keyusage-success/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/signing-vendor-certificate-without-keyusage-success/data.txt");
        final var signature = readFile("signature/signing-vendor-certificate-without-keyusage-success/signature.cms");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature));
    }

    @Test
    public void shouldSucceedVerificationWithTrustedCertificateWithoutKeyUsage() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signing-trusted-certificate-without-keyusage-success/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/signing-trusted-certificate-without-keyusage-success/data.txt");
        final var signature = readFile("signature/signing-trusted-certificate-without-keyusage-success/signature.cms");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature));
    }

    @Test
    public void shouldFailVerificationWithVendorCertificateWithoutDigitalSignatureKeyUsageAndValidationEnabled() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signing-vendor-certificate-without-digsig-keyusage/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/signing-vendor-certificate-without-digsig-keyusage/data.txt");
        final var signature = readFile("signature/signing-vendor-certificate-without-digsig-keyusage/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Could not find valid trusted certificate for signature "
                                    + "[Certificate issuer: CN=Root CA, serial number: 63EA197D23287B4A269B028C7B4A5270D10F53D5]");
    }

    @Test
    public void shouldFailVerificationWithTrustedCertificateWithoutDigitalSignatureKeyUsageAndValidationEnabled() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signing-trusted-certificate-without-digsig-keyusage/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/signing-trusted-certificate-without-digsig-keyusage/data.txt");
        final var signature = readFile("signature/signing-trusted-certificate-without-digsig-keyusage/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Could not find valid trusted certificate for signature "
                                    + "[Certificate issuer: CN=Root CA, serial number: 1608B08633514C78138911851475C508685DE5F5]");
    }

    @Test
    public void shouldSucceedVerificationWithVendorCertificateWithoutDigitalSignatureKeyUsageAndValidationDisabled() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signing-vendor-certificate-without-digsig-keyusage/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, true);

        final var contentStream = openInputStream("signature/signing-vendor-certificate-without-digsig-keyusage/data.txt");
        final var signature = readFile("signature/signing-vendor-certificate-without-digsig-keyusage/signature.cms");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature));
    }

    @Test
    public void shouldSucceedVerificationWithTrustedCertificateWithoutDigitalSignatureKeyUsageAndValidationDisabled() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signing-trusted-certificate-without-digsig-keyusage/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, true);

        final var contentStream = openInputStream("signature/signing-trusted-certificate-without-digsig-keyusage/data.txt");
        final var signature = readFile("signature/signing-trusted-certificate-without-digsig-keyusage/signature.cms");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature));
    }

    @Test
    public void shouldFailVerificationWithSignatureContainerMissingCms() {
        // given
        final var signatureService = new SignatureServiceImpl(new TrustStoreServiceNoOpImpl(), false, false);

        final var contentStream = openInputStream("signature/signature-container-missing-cms-failure/data.txt");
        final var signature = readFile("signature/signature-container-missing-cms-failure/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Provided PEM string does not contain expected object types CMS, PKCS7");
    }

    @Test
    public void shouldFailVerificationWithSignatureContainerHavingMultipleCms() {
        // given
        final var signatureService = new SignatureServiceImpl(new TrustStoreServiceNoOpImpl(), false, false);

        final var contentStream = openInputStream("signature/signature-container-has-multiple-cms-failure/data.txt");
        final var signature = readFile("signature/signature-container-has-multiple-cms-failure/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Provided PEM string contains more than one object of types CMS, PKCS7");
    }

    @Test
    public void shouldFailVerificationWithSignatureHavingContent() {
        // given
        final var signatureService = new SignatureServiceImpl(new TrustStoreServiceNoOpImpl(), false, false);

        final var contentStream = openInputStream("signature/signature-has-content-failure/data.txt");
        final var signature = readFile("signature/signature-has-content-failure/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("CMS contains signed content");
    }

    @Test
    public void shouldFailVerificationWithSignatureHavingCRL() {
        // given
        final var signatureService = new SignatureServiceImpl(new TrustStoreServiceNoOpImpl(), false, false);

        final var contentStream = openInputStream("signature/signature-has-crl-failure/data.txt");
        final var signature = readFile("signature/signature-has-crl-failure/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("CMS contains one or more CRLs");
    }

    @Test
    public void shouldFailVerificationWithSignatureContainerHavingCRLAndValidationEnabled() {
        // given
        final var signatureService = new SignatureServiceImpl(new TrustStoreServiceNoOpImpl(), false, false);

        final var contentStream = openInputStream("signature/signature-container-has-crl/data.txt");
        final var signature = readFile("signature/signature-container-has-crl/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("PEM string contains CRL(s) which is not expected there");
    }

    @Test
    public void shouldSucceedVerificationWithSignatureContainerHavingCRLAndValidationDisabled() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signature-container-has-crl/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, true, false);

        final var contentStream = openInputStream("signature/signature-container-has-crl/data.txt");
        final var signature = readFile("signature/signature-container-has-crl/signature.cms");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature));
    }

    @Test
    public void shouldFailVerificationWithSignatureContainerHavingCRLAndOtherObjectAndValidationEnabled() {
        // given
        final var signatureService = new SignatureServiceImpl(new TrustStoreServiceNoOpImpl(), false, false);

        final var contentStream = openInputStream("signature/signature-container-has-crl-and-other-failure/data.txt");
        final var signature = readFile("signature/signature-container-has-crl-and-other-failure/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("PEM string contains CRL(s) which is not expected there");
    }

    @Test
    public void shouldFailVerificationWithSignatureContainerHavingCRLAndOtherObjectAndValidationDisabled() {
        // given
        final var signatureService = new SignatureServiceImpl(new TrustStoreServiceNoOpImpl(), true, false);

        final var contentStream = openInputStream("signature/signature-container-has-crl-and-other-failure/data.txt");
        final var signature = readFile("signature/signature-container-has-crl-and-other-failure/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("PEM string contains unexpected object types CERTIFICATE");
    }

    @Test
    public void shouldFailVerificationWithVendorCertificateContainerHavingCRLAndValidationEnabled() {
        // given
        final var signatureService = new SignatureServiceImpl(new TrustStoreServiceNoOpImpl(), false, false);

        final var contentStream = openInputStream("signature/certificate-container-has-crl/data.txt");
        final var signature = readFile("signature/certificate-container-has-crl/signature.cms");
        final var certificate = readFile("signature/certificate-container-has-crl/certificate.pem");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature, certificate))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("PEM string contains CRL(s) which is not expected there");
    }

    @Test
    public void shouldSucceedVerificationWithVendorCertificateContainerHavingCRLAndValidationDisabled() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/certificate-container-has-crl/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, true, false);

        final var contentStream = openInputStream("signature/certificate-container-has-crl/data.txt");
        final var signature = readFile("signature/certificate-container-has-crl/signature.cms");
        final var certificate = readFile("signature/certificate-container-has-crl/certificate.pem");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature, certificate));
    }

    @Test
    public void shouldFailVerificationWithVendorCertificateContainerHavingCRLAndOtherObjectAndValidationEnabled() {
        // given
        final var signatureService = new SignatureServiceImpl(new TrustStoreServiceNoOpImpl(), false, false);

        final var contentStream = openInputStream("signature/certificate-container-has-crl-and-other-failure/data.txt");
        final var signature = readFile("signature/certificate-container-has-crl-and-other-failure/signature.cms");
        final var certificate = readFile("signature/certificate-container-has-crl-and-other-failure/certificate.pem");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature, certificate))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("PEM string contains CRL(s) which is not expected there");
    }

    @Test
    public void shouldFailVerificationWithVendorCertificateContainerHavingCRLAndOtherObjectAndValidationDisabled() {
        // given
        final var signatureService = new SignatureServiceImpl(new TrustStoreServiceNoOpImpl(), true, false);

        final var contentStream = openInputStream("signature/certificate-container-has-crl-and-other-failure/data.txt");
        final var signature = readFile("signature/certificate-container-has-crl-and-other-failure/signature.cms");
        final var certificate = readFile("signature/certificate-container-has-crl-and-other-failure/certificate.pem");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature, certificate))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("PEM string contains unexpected object types CMS");
    }

    @Test
    public void shouldFailVerificationWithVendorCertificateHavingCrlDistributionPointsAndValidationEnabled() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signing-vendor-certificate-has-crldistpoints/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/signing-vendor-certificate-has-crldistpoints/data.txt");
        final var signature = readFile("signature/signing-vendor-certificate-has-crldistpoints/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Could not find valid trusted certificate for signature "
                                    + "[Certificate issuer: CN=Root CA, serial number: 259E7D73B279015D75E6681184B2EAE1D4D3886C]");
    }

    @Test
    public void shouldFailVerificationWithTrustedCertificateHavingCrlDistributionPointsAndValidationEnabled() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signing-trusted-certificate-has-crldistpoints/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/signing-trusted-certificate-has-crldistpoints/data.txt");
        final var signature = readFile("signature/signing-trusted-certificate-has-crldistpoints/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Could not find valid trusted certificate for signature "
                                    + "[Certificate issuer: CN=Intermediate 1 CA, serial number: 582A6783049BC07FF1A30215A23679F4031AF7AD]");
    }

    @Test
    public void shouldSucceedVerificationWithVendorCertificateHavingCrlDistributionPointsAndValidationDisabled() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signing-vendor-certificate-has-crldistpoints/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, true, false);

        final var contentStream = openInputStream("signature/signing-vendor-certificate-has-crldistpoints/data.txt");
        final var signature = readFile("signature/signing-vendor-certificate-has-crldistpoints/signature.cms");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature));
    }

    @Test
    public void shouldSucceedVerificationWithTrustedCertificateHavingCrlDistributionPointsAndValidationDisabled() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signing-trusted-certificate-has-crldistpoints/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, true, false);

        final var contentStream = openInputStream("signature/signing-trusted-certificate-has-crldistpoints/data.txt");
        final var signature = readFile("signature/signing-trusted-certificate-has-crldistpoints/signature.cms");

        // when and then
        assertThatNoException().isThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature));
    }

    @Test
    public void shouldFailVerificationWithVendorCertificateExpired() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signing-vendor-certificate-expired-failure/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/signing-vendor-certificate-expired-failure/data.txt");
        final var signature = readFile("signature/signing-vendor-certificate-expired-failure/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Could not find valid trusted certificate for signature "
                                    + "[Certificate issuer: CN=Root CA, serial number: 259E7D73B279015D75E6681184B2EAE1D4D3886E]");
    }

    @Test
    public void shouldFailVerificationWithTrustedCertificateExpired() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signing-trusted-certificate-expired-failure/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/signing-trusted-certificate-expired-failure/data.txt");
        final var signature = readFile("signature/signing-trusted-certificate-expired-failure/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Could not find valid trusted certificate for signature "
                                    + "[Certificate issuer: CN=Intermediate 1 CA, serial number: 582A6783049BC07FF1A30215A23679F4031AF7AE]");
    }

    @Test
    public void shouldFailVerificationWithVendorCertificateNonV3() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signing-vendor-certificate-non-v3-failure/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/signing-vendor-certificate-non-v3-failure/data.txt");
        final var signature = readFile("signature/signing-vendor-certificate-non-v3-failure/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Could not find valid trusted certificate for signature "
                                    + "[Certificate issuer: CN=Root CA, serial number: 259E7D73B279015D75E6681184B2EAE1D4D38871]");
    }

    @Test
    public void shouldFailVerificationWithTrustedCertificateNonV3() {
        // given
        final var trustStoreService = new TrustStoreServiceLocalImpl("signature/signing-trusted-certificate-non-v3-failure/ca.pem");
        final var signatureService = new SignatureServiceImpl(trustStoreService, false, false);

        final var contentStream = openInputStream("signature/signing-trusted-certificate-non-v3-failure/data.txt");
        final var signature = readFile("signature/signing-trusted-certificate-non-v3-failure/signature.cms");

        // when and then
        assertThatThrownBy(() -> signatureService.verifyContentSignature(contentStream, signature))
                .isInstanceOf(SignatureVerificationException.class)
                .hasMessage("Could not find valid trusted certificate for signature "
                                    + "[Certificate issuer: CN=Intermediate 1 CA, serial number: 582A6783049BC07FF1A30215A23679F4031AF7AF]");
    }
}
