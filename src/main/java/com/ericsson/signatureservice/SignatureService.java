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

import java.io.InputStream;

import com.ericsson.signatureservice.exception.SignatureVerificationException;

/**
 * A service for signed content verification.
 */
public interface SignatureService {

    /**
     * Verifies content using signature and certificate.
     *
     * @param content     to be verified
     * @param signature   to be used to verify content; might contain certificate
     * @param certificate certificate(s) to be used to validate signature
     * @throws SignatureVerificationException if signature verification fails
     */
    void verifyContentSignature(InputStream content, String signature, String certificate) throws SignatureVerificationException;

    /**
     * Verifies content using signature and certificate (from signature container).
     *
     * @param content   to be verified
     * @param signature to be used to verify content; should contain certificate(s)
     * @throws SignatureVerificationException if signature verification fails
     */
    void verifyContentSignature(InputStream content, String signature) throws SignatureVerificationException;
}
