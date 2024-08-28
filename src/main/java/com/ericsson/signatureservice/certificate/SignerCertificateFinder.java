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

import static com.ericsson.signatureservice.certificate.CertificateHelper.asString;

import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import com.ericsson.signatureservice.ca.TrustStoreService;
import com.ericsson.signatureservice.exception.SignatureVerificationException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SignerCertificateFinder {

    private final TrustStoreService trustStoreService;
    private final CertificateValidator certificateValidator;
    private final CertificateTrustVerifier certificateTrustVerifier;

    public SignerCertificateFinder(final TrustStoreService trustStoreService,
                                   final boolean ignoreCrlInfo,
                                   final boolean skipCertificateKeyUsageValidation) {

        this.trustStoreService = trustStoreService;
        this.certificateValidator = new CertificateValidator(ignoreCrlInfo, skipCertificateKeyUsageValidation);
        this.certificateTrustVerifier = new CertificateTrustVerifier(trustStoreService, certificateValidator);
    }

    public Optional<X509Certificate> findAndValidate(final X509CertSelector certSelector, final CertStore vendorCertificatesStore) {
        return findAndValidateCertificateBySelector(certSelector, vendorCertificatesStore)
                .filter(certificateValidator::hasSignerCertificateValidKeyUsage);
    }

    private Optional<X509Certificate> findAndValidateCertificateBySelector(final X509CertSelector certSelector,
                                                                           final CertStore vendorCertificatesStore) {

        final var vendorCertificate = lookupCertificateFromVendorStore(certSelector, vendorCertificatesStore);

        vendorCertificate.ifPresent(certificate -> LOGGER.info("Signing certificate [{}] is valid and trusted", asString(certificate)));

        return vendorCertificate
                .or(() -> lookupSigningCertificateFromTrustStore(certSelector));
    }

    private Optional<X509Certificate> lookupCertificateFromVendorStore(final X509CertSelector certSelector, final CertStore vendorCertificatesStore) {
        LOGGER.info("Searching for signing certificate among vendor certificates");

        final var vendorCertificate = lookupCertificatesFromStore(certSelector, vendorCertificatesStore).stream().findFirst();

        vendorCertificate.ifPresent(certificate -> LOGGER.info("Found signing vendor certificate [{}]", asString(certificate)));

        return vendorCertificate
                .filter(certificate -> isVendorCertificateValidAndTrusted(certificate, vendorCertificatesStore));
    }

    private boolean isVendorCertificateValidAndTrusted(final X509Certificate vendorCertificate, final CertStore vendorCertificatesStore) {
        final var validVendorCertificates = validCertificatesFromStore(vendorCertificatesStore);

        if (!validVendorCertificates.contains(vendorCertificate)) {
            LOGGER.warn("Signer vendor certificate [{}] is not valid", asString(vendorCertificate));

            return false;
        }

        return certificateTrustVerifier.isCertificateTrusted(vendorCertificate, validVendorCertificates);
    }

    private List<X509Certificate> validCertificatesFromStore(final CertStore vendorCertificatesStore) {
        return lookupCertificatesFromStore(null, vendorCertificatesStore).stream()
                .filter(certificateValidator::isCertificateValid)
                .collect(Collectors.toList());
    }

    private Optional<X509Certificate> lookupSigningCertificateFromTrustStore(final X509CertSelector certSelector) {
        LOGGER.info("Looking up signing certificate in trust store");

        final var trustStoreCertificate = trustStoreService.getCertificateBySelector(certSelector);

        trustStoreCertificate.ifPresent(certificate -> LOGGER.info("Found signing certificate in trust store: [{}]", asString(certificate)));

        return trustStoreCertificate
                .filter(certificateValidator::isCertificateValid);
    }

    private static Collection<X509Certificate> lookupCertificatesFromStore(final CertSelector certSelector,
                                                                           final CertStore vendorCertificatesStore) {
        try {
            return vendorCertificatesStore.getCertificates(certSelector).stream()
                    .map(certificate -> (X509Certificate) certificate)
                    .collect(Collectors.toList());
        } catch (final CertStoreException e) {
            throw new SignatureVerificationException(format("Could not lookup a certificate [%s] from store", certSelector.toString()), e);
        }
    }
}
