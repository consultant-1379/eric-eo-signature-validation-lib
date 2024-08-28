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
package com.ericsson.signatureservice.cms;

import static com.ericsson.signatureservice.Constants.BOUNCY_CASTLE_PROVIDER;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.ericsson.signatureservice.exception.SignatureVerificationException;
import com.ericsson.signatureservice.pem.PemReader;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CmsReader {

    private final boolean ignoreCrlInfo;
    private final PemReader pemReader;
    private final DigestCalculatorProvider digestCalculatorProvider;

    public CmsReader(final boolean ignoreCrlInfo) {
        this.ignoreCrlInfo = ignoreCrlInfo;
        this.pemReader = new PemReader(ignoreCrlInfo);
        this.digestCalculatorProvider = createDigestCalculatorProvider();
    }

    public CMSSignedDataParser readFromInputStream(final InputStream content, final String signature) {
        LOGGER.info("Reading CMS signature");

        final var cmsBytes = pemReader.readCmsBytesFromPemString(signature);

        validate(cmsBytes);

        return createCmsSignedDataParser(content, cmsBytes);
    }

    private void validate(final byte[] cmsBytes) {
        final CMSSignedData cms;
        try {
            cms = new CMSSignedData(cmsBytes);
        } catch (CMSException e) {
            throw new SignatureVerificationException("Could not read CMS", e);
        }

        if (!cms.getCRLs().getMatches(null).isEmpty()) {
            if (ignoreCrlInfo) {
                LOGGER.warn("CMS contains one or more CRLs");
            } else {
                throw new SignatureVerificationException("CMS contains one or more CRLs");
            }
        }

        if (cms.getSignedContent() != null) {
            throw new SignatureVerificationException("CMS contains signed content");
        }

        if (cms.getSignerInfos().size() == 0) {
            throw new SignatureVerificationException("CMS does not contains any signatures");
        }
    }

    private CMSSignedDataParser createCmsSignedDataParser(final InputStream content, final byte[] cmsBytes) {
        try {
            final var cmsSignedDataParser = new CMSSignedDataParser(digestCalculatorProvider, new CMSTypedStream(content), cmsBytes);

            cmsSignedDataParser.getSignedContent().drain();

            return cmsSignedDataParser;
        } catch (final CMSException | IOException e) {
            throw new SignatureVerificationException("Could not read CMS and/or detached content", e);
        }
    }

    private static DigestCalculatorProvider createDigestCalculatorProvider() {
        try {
            return new JcaDigestCalculatorProviderBuilder().setProvider(BOUNCY_CASTLE_PROVIDER).build();
        } catch (final OperatorCreationException e) {
            throw new RuntimeException("Could not create digest calculator provider", e);
        }
    }
}
