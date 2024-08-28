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

import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Optional;

/**
 * A service providing access to certificates in trust store
 */
public interface TrustStoreService {

    /**
     * Look up single certificate by selector (for example issuer/serial number pair or subject key identifier). May be used for finding a
     * certificate that had been used to sign content.
     *
     * @param certSelector Certificate selector for matching
     * @return @{@link Optional<X509Certificate>} with certificate if it is found or empty otherwise
     */
    Optional<X509Certificate> getCertificateBySelector(X509CertSelector certSelector);

    /**
     * Look up certificate(s) by subject. May be used for finding a certificate that had been used to sign another certificate.
     *
     * @param subject Subject of the certificate(s)
     * @return @{@link Collection<X509Certificate>} of found certificates, may be empty
     */
    Collection<X509Certificate> getCertificatesBySubject(String subject);
}
