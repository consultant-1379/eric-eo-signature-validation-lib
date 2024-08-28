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

import static java.util.Collections.emptyList;

import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Optional;

import com.ericsson.signatureservice.ca.TrustStoreService;

public class TrustStoreServiceNoOpImpl implements TrustStoreService {

    @Override
    public Optional<X509Certificate> getCertificateBySelector(final X509CertSelector certSelector) {
        return Optional.empty();
    }

    @Override
    public Collection<X509Certificate> getCertificatesBySubject(final String subject) {
        return emptyList();
    }
}
