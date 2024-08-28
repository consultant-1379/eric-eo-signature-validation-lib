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

import static com.ericsson.signatureservice.Constants.COLLECTION_CERT_STORE_TYPE;
import static com.ericsson.signatureservice.Constants.X509_CERTIFICATE_TYPE;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;

import com.ericsson.signatureservice.exception.SignatureVerificationException;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CertificateHelper {

    public static CertStore createCertStore(final Collection<X509Certificate> certificates) {
        try {
            return CertStore.getInstance(COLLECTION_CERT_STORE_TYPE, new CollectionCertStoreParameters(certificates));
        } catch (final InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new SignatureVerificationException("Could not create cert store", e);
        }
    }

    public static CertificateFactory createCertificateFactory() {
        try {
            return CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
        } catch (final CertificateException e) {
            throw new RuntimeException("Could not create certificate factory", e);
        }
    }

    public static String asString(final X509Certificate certificate) {
        return format("Subject: %s, issuer: %s, serial number: %X",
                      certificate.getSubjectDN().getName(),
                      certificate.getIssuerDN().getName(),
                      certificate.getSerialNumber());
    }
}
