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

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Constants {

    public static final String BOUNCY_CASTLE_PROVIDER = "BC";
    public static final String COLLECTION_CERT_STORE_TYPE = "Collection";
    public static final String X509_CERTIFICATE_TYPE = "X.509";
    public static final int CERTIFICATE_V3 = 3;
    public static final String VALIDATOR_ALGORITHM = "PKIX";
}
