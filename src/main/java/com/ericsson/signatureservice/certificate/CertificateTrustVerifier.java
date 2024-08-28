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
package com.ericsson.signatureservice.certificate;

import static java.lang.String.format;

import static com.ericsson.signatureservice.Constants.VALIDATOR_ALGORITHM;
import static com.ericsson.signatureservice.certificate.CertificateHelper.asString;
import static com.ericsson.signatureservice.certificate.CertificateHelper.createCertStore;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.security.auth.x500.X500Principal;

import com.ericsson.signatureservice.ca.TrustStoreService;
import com.ericsson.signatureservice.exception.SignatureVerificationException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CertificateTrustVerifier {

    private final TrustStoreService trustStoreService;
    private final CertificateValidator certificateValidator;

    public CertificateTrustVerifier(final TrustStoreService trustStoreService, final CertificateValidator certificateValidator) {
        this.trustStoreService = trustStoreService;
        this.certificateValidator = certificateValidator;
    }

    public boolean isCertificateTrusted(final X509Certificate vendorCertificate, final List<X509Certificate> validVendorCertificates) {
        LOGGER.info("Checking if vendor certificate [{}] is trusted", asString(vendorCertificate));

        final var validTrustStoreCertificates = findValidIssuersCertificatesInTrustStore(validVendorCertificates);
        if (validTrustStoreCertificates.isEmpty()) {
            LOGGER.warn("No valid trusted certificates found for leaf certificate [{}]", asString(vendorCertificate));

            return false;
        }

        try {
            final var certPathValidator = CertPathBuilder.getInstance(VALIDATOR_ALGORITHM);
            final var validationParameters = createCertPathValidationParams(vendorCertificate, validVendorCertificates, validTrustStoreCertificates);

            certPathValidator.build(validationParameters);

            return true;
        } catch (final NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new SignatureVerificationException(format("Could not create certificate path to validate for certificate [%s]",
                                                            asString(vendorCertificate)),
                                                     e);
        } catch (final CertPathBuilderException e) {
            LOGGER.warn("Certificate [{}] verification failed", asString(vendorCertificate), e);

            return false;
        }
    }

    private Set<X509Certificate> findValidIssuersCertificatesInTrustStore(final List<X509Certificate> validVendorCertificates) {
        LOGGER.info("Looking up for valid issuers' certificates in trust store");

        final var issuers = validVendorCertificates.stream()
                .map(X509Certificate::getIssuerX500Principal)
                .map(X500Principal::getName)
                .collect(Collectors.toSet());

        return issuers.stream()
                .map(trustStoreService::getCertificatesBySubject)
                .flatMap(Collection::stream)
                .filter(certificateValidator::isCertificateValid)
                .collect(Collectors.toSet());
    }

    private static PKIXBuilderParameters createCertPathValidationParams(final X509Certificate vendorCertificate,
                                                                        final List<X509Certificate> validVendorCertificates,
                                                                        final Set<X509Certificate> validTrustStoreCertificates)
            throws InvalidAlgorithmParameterException {

        final var targetCertSelector = toCertSelector(vendorCertificate);
        final var intermediateCertStore = createCertStore(validVendorCertificates);
        final var trustAnchors = toTrustAnchors(validTrustStoreCertificates);

        final var validationParameters = new PKIXBuilderParameters(trustAnchors, targetCertSelector);
        validationParameters.addCertStore(intermediateCertStore);
        validationParameters.setRevocationEnabled(false);

        return validationParameters;
    }

    private static Set<TrustAnchor> toTrustAnchors(final Set<X509Certificate> validTrustStoreCertificates) {
        return validTrustStoreCertificates.stream()
                .map(certificate -> new TrustAnchor(certificate, null))
                .collect(Collectors.toSet());
    }

    private static X509CertSelector toCertSelector(final X509Certificate vendorCertificate) {
        final var targetCertSelector = new X509CertSelector();
        targetCertSelector.setCertificate(vendorCertificate);

        return targetCertSelector;
    }
}
