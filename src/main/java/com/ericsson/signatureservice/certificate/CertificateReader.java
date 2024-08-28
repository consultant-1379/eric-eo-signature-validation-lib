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

import static java.util.Collections.emptyList;

import static com.ericsson.signatureservice.Constants.BOUNCY_CASTLE_PROVIDER;
import static com.ericsson.signatureservice.certificate.CertificateHelper.createCertStore;
import static com.ericsson.signatureservice.certificate.CertificateHelper.createCertificateFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.util.Store;

import com.ericsson.signatureservice.exception.SignatureVerificationException;
import com.ericsson.signatureservice.pem.PemReader;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CertificateReader {

    private static final JcaX509CertificateConverter JCA_X509_CERTIFICATE_CONVERTER =
            new JcaX509CertificateConverter().setProvider(BOUNCY_CASTLE_PROVIDER);

    private final PemReader pemReader;
    private final CertificateFactory certificateFactory;

    public CertificateReader(final boolean ignoreCrlInfo) {
        this.pemReader = new PemReader(ignoreCrlInfo);
        this.certificateFactory = createCertificateFactory();
    }

    public CertStore collectAllCertificates(final CMSSignedDataParser cms, final String certificate) {
        LOGGER.info("Reading certificates from CMS signature and certificate container");

        final var certificatesInCms = readCertificatesFromCms(cms);
        LOGGER.info("Found {} certificates in CMS signature", certificatesInCms.size());

        final var externalCertificates = readCertificatesFromPemString(certificate);
        LOGGER.info("Found {} certificates in certificate container", externalCertificates.size());

        final var combinedCertificates = Stream
                .concat(certificatesInCms.stream(), externalCertificates.stream())
                .collect(Collectors.toList());
        LOGGER.info("Found total of {} certificates", combinedCertificates.size());

        return createCertStore(combinedCertificates);
    }

    private static List<X509Certificate> readCertificatesFromCms(final CMSSignedDataParser cms) {
        return certificatesFromCms(cms).getMatches(null).stream()
                .map(CertificateReader::toX509Certificate)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    @SuppressWarnings("unchecked")
    private static Store<X509CertificateHolder> certificatesFromCms(final CMSSignedDataParser cms) {
        try {
            return (Store<X509CertificateHolder>) cms.getCertificates();
        } catch (final CMSException e) {
            throw new SignatureVerificationException("Could not get certificates from CMS", e);
        }
    }

    @SuppressWarnings("unchecked")
    private Collection<X509Certificate> readCertificatesFromPemString(final String certificate) {
        if (StringUtils.isEmpty(certificate)) {
            return emptyList();
        }

        try (var is = new ByteArrayInputStream(pemReader.readCertificatesBytesFromPemString(certificate))) {
            return (Collection<X509Certificate>) certificateFactory.generateCertificates(is);
        } catch (final IOException | CertificateException e) {
            throw new SignatureVerificationException("Could not read certificates from PEM string", e);
        }
    }

    private static X509Certificate toX509Certificate(final X509CertificateHolder holder) {
        try {
            return JCA_X509_CERTIFICATE_CONVERTER.getCertificate(holder);
        } catch (final CertificateException e) {
            LOGGER.warn("Could not convert certificate", e);

            return null;
        }
    }
}
