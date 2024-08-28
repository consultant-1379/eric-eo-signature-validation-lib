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

import static java.lang.String.format;

import static org.bouncycastle.util.encoders.Hex.toHexString;

import static com.ericsson.signatureservice.Constants.BOUNCY_CASTLE_PROVIDER;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import com.ericsson.signatureservice.ca.TrustStoreService;
import com.ericsson.signatureservice.certificate.CertificateReader;
import com.ericsson.signatureservice.certificate.SignerCertificateFinder;
import com.ericsson.signatureservice.cms.CmsReader;
import com.ericsson.signatureservice.exception.SignatureVerificationException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SignatureServiceImpl implements SignatureService {

    private final CmsReader cmsReader;
    private final CertificateReader certificateReader;
    private final SignerCertificateFinder signerCertificateFinder;

    public SignatureServiceImpl(final TrustStoreService trustStoreService,
                                final boolean ignoreCrlInfo,
                                final boolean skipCertificateKeyUsageValidation) {

        Security.addProvider(new BouncyCastleProvider());

        cmsReader = new CmsReader(ignoreCrlInfo);
        certificateReader = new CertificateReader(ignoreCrlInfo);
        signerCertificateFinder = new SignerCertificateFinder(trustStoreService, ignoreCrlInfo, skipCertificateKeyUsageValidation);
    }

    @Override
    public void verifyContentSignature(final InputStream content,
                                       final String signature,
                                       final String certificate) throws SignatureVerificationException {

        LOGGER.info("Beginning content signature verification");

        final var cms = cmsReader.readFromInputStream(content, signature);
        final var vendorCertificatesStore = certificateReader.collectAllCertificates(cms, certificate);

        for (final var signer : signersFromCms(cms)) {
            verifySignature(signer, vendorCertificatesStore);
        }

        LOGGER.info("Successfully verified content signature");
    }

    @Override
    public void verifyContentSignature(final InputStream content, final String signature) throws SignatureVerificationException {
        verifyContentSignature(content, signature, null);
    }

    private void verifySignature(final SignerInformation signer, final CertStore vendorCertificatesStore) {
        final var signerAsString = asString(signer);

        LOGGER.info("Verifying signature [{}]", signerAsString);

        final var signerCertificate = signerCertificateFinder.findAndValidate(toCertSelector(signer.getSID()), vendorCertificatesStore);

        if (signerCertificate.isEmpty()) {
            throw new SignatureVerificationException(format("Could not find valid trusted certificate for signature [%s]", signerAsString));
        }

        if (!verifySignatureWithCertificate(signer, signerCertificate.get())) {
            throw new SignatureVerificationException(format("Content's signature [%s] failed verification", signerAsString));
        }

        LOGGER.info("Signature [{}] is valid", signerAsString);
    }

    private static X509CertSelector toCertSelector(final SignerId signerId) {
        final X509CertSelector certSelector = new X509CertSelector();
        if (signerId.getIssuer() != null) {
            certSelector.setIssuer(toPrincipal(signerId.getIssuer()));
        }
        if (signerId.getSerialNumber() != null) {
            certSelector.setSerialNumber(signerId.getSerialNumber());
        }
        if (signerId.getSubjectKeyIdentifier() != null) {
            certSelector.setSubjectKeyIdentifier(toOctetString(signerId.getSubjectKeyIdentifier()));
        }

        return certSelector;
    }

    private static boolean verifySignatureWithCertificate(final SignerInformation signer, final X509Certificate signerCertificate) {
        try {
            return signer.verify(createSignerInfoVerifier(signerCertificate));
        } catch (final CMSSignerDigestMismatchException e) {
            LOGGER.warn("Content's digest is different from the digest in signature [{}]", asString(signer), e);

            return false;
        } catch (final CMSException e) {
            throw new SignatureVerificationException(format("Could not verify content's signature [%s]", asString(signer)), e);
        }
    }

    private static SignerInformationVerifier createSignerInfoVerifier(final X509Certificate signerCertificate) {
        try {
            return new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(BOUNCY_CASTLE_PROVIDER)
                    .build(signerCertificate);
        } catch (final OperatorCreationException e) {
            throw new SignatureVerificationException("Could not create signer info verifier", e);
        }
    }

    private Iterable<SignerInformation> signersFromCms(final CMSSignedDataParser cms) {
        try {
            return cms.getSignerInfos().getSigners();
        } catch (final CMSException e) {
            throw new SignatureVerificationException("Could not get signers from CMS", e);
        }
    }

    private static String asString(final SignerInformation signer) {
        final var sid = signer.getSID();

        if (sid.getIssuer() != null && sid.getSerialNumber() != null) {
            return format("Certificate issuer: %s, serial number: %X", sid.getIssuer().toString(), sid.getSerialNumber());
        } else if (sid.getSubjectKeyIdentifier() != null) {
            return format("Certificate subject key identifier: %s", toHexString(sid.getSubjectKeyIdentifier()).toUpperCase());
        }

        throw new SignatureVerificationException(
                "Signature does not container neither certificate issuer/serial number pair nor subject key identifier");
    }

    private static X500Principal toPrincipal(final X500Name issuer) {
        try {
            return new X500Principal(issuer.getEncoded());
        } catch (final IOException e) {
            throw new SignatureVerificationException(format("Could not construct principal from issuer [%s]", issuer), e);
        }
    }

    private static byte[] toOctetString(final byte[] contents) {
        try {
            return new DEROctetString(contents).getEncoded();
        } catch (final IOException e) {
            throw new SignatureVerificationException("Could not create octet string", e);
        }
    }
}
