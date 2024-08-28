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

import static com.ericsson.signatureservice.certificate.CertificateHelper.asString;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.bouncycastle.asn1.x509.Extension;

import com.ericsson.signatureservice.Constants;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CertificateValidator {

    private final boolean ignoreCrlInfo;
    private final boolean skipCertificateKeyUsageValidation;

    public CertificateValidator(final boolean ignoreCrlInfo,
                                final boolean skipCertificateKeyUsageValidation) {

        this.ignoreCrlInfo = ignoreCrlInfo;
        this.skipCertificateKeyUsageValidation = skipCertificateKeyUsageValidation;
    }

    public boolean isCertificateValid(final X509Certificate certificate) {
        return isCertificateV3(certificate) && isCertificateNotExpired(certificate) && hasCertificateNoUnsupportedExtensions(certificate);
    }

    public boolean hasSignerCertificateValidKeyUsage(final X509Certificate certificate) {
        if (skipCertificateKeyUsageValidation) {
            return true;
        }

        final var keyUsage = certificate.getKeyUsage();
        if (keyUsage == null) {
            return true;
        }

        if (!keyUsage[0]) {
            LOGGER.warn("Certificate [{}] has key usages defined but digitalSignature is not among them", asString(certificate));

            return false;
        }

        return true;
    }

    private static boolean isCertificateV3(final X509Certificate certificate) {
        final var version = certificate.getVersion();
        if (version != Constants.CERTIFICATE_V3) {
            LOGGER.warn("Certificate [{}] has invalid version {}", asString(certificate), version);

            return false;
        }

        return true;
    }

    private static boolean isCertificateNotExpired(final X509Certificate certificate) {
        try {
            certificate.checkValidity();

            return true;
        } catch (final CertificateExpiredException | CertificateNotYetValidException e) {
            LOGGER.warn("Certificate [{}] is expired or not yet valid. notBefore {}, notAfter {}",
                        asString(certificate),
                        certificate.getNotBefore(),
                        certificate.getNotAfter());

            return false;
        }
    }

    private boolean hasCertificateNoUnsupportedExtensions(final X509Certificate certificate) {
        if (ignoreCrlInfo) {
            return true;
        }

        final var result = hasNoCrlExtensions(certificate.getCriticalExtensionOIDs())
                && hasNoCrlExtensions(certificate.getNonCriticalExtensionOIDs());

        if (!result) {
            LOGGER.warn("Certificate [{}] has unsupported cRLDistributionPoints and/or freshestCRL extensions", asString(certificate));
        }

        return result;
    }

    private static boolean hasNoCrlExtensions(final Set<String> extensionOids) {
        if (extensionOids == null || extensionOids.isEmpty()) {
            return true;
        }

        return !(extensionOids.contains(Extension.cRLDistributionPoints.getId()) || extensionOids.contains(Extension.freshestCRL.getId()));
    }
}
