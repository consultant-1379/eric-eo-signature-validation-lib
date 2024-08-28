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

import static java.util.Collections.emptyList;

import static com.ericsson.signatureservice.certificate.CertificateHelper.createCertStore;
import static com.ericsson.signatureservice.certificate.CertificateHelper.createCertificateFactory;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.io.filefilter.SuffixFileFilter;

import lombok.extern.slf4j.Slf4j;

/**
 * {@link TrustStoreService} implementation backed by a classpath resource or a file (directory with files) on a local filesystem.
 */
@Slf4j
public class TrustStoreServiceLocalImpl implements TrustStoreService {

    private static final String PEM_EXTENSION = ".pem";

    private final CertificateFactory certificateFactory;
    private final String caPath;

    public TrustStoreServiceLocalImpl(final String caPath) {
        this.caPath = caPath;
        this.certificateFactory = createCertificateFactory();
    }

    @Override
    public Optional<X509Certificate> getCertificateBySelector(final X509CertSelector certSelector) {
        try {
            return createCaCertStore().getCertificates(certSelector).stream()
                    .map(certificate -> (X509Certificate) certificate)
                    .findFirst();
        } catch (final CertStoreException e) {
            LOGGER.error("Could not get a certificate from the trust store by selector: {}", certSelector.toString(), e);
        }

        return Optional.empty();
    }

    @Override
    public Collection<X509Certificate> getCertificatesBySubject(final String subject) {
        final var certSelector = new X509CertSelector();
        certSelector.setSubject(new X500Principal(subject));

        try {
            return createCaCertStore().getCertificates(certSelector).stream()
                    .map(certificate -> (X509Certificate) certificate)
                    .collect(Collectors.toList());
        } catch (final CertStoreException e) {
            LOGGER.error("Could not get certificates by subject {} from the trust store", subject, e);
        }

        return emptyList();
    }

    private CertStore createCaCertStore() {
        return createCertStore(extractCertificatesFromPath(this.caPath));
    }

    private Collection<X509Certificate> extractCertificatesFromPath(final String caPath) {
        final var certificates = listCertificateFilesByCaPath(caPath)
                .map(this::extractCertificatesFromFile)
                .flatMap(Collection::stream)
                .collect(Collectors.toList());

        LOGGER.info("Initialized trust store service from CA path {}, read {} certificates", caPath, certificates.size());

        return certificates;
    }

    @SuppressWarnings("unchecked")
    private Collection<X509Certificate> extractCertificatesFromFile(final Path filePath) {
        LOGGER.info("Reading certificates from file {}", filePath);

        try (var is = Files.newInputStream(filePath)) {
            final var certificates = (Collection<X509Certificate>) certificateFactory.generateCertificates(is);

            LOGGER.info("Successfully read {} certificates from file {}", certificates.size(), filePath);

            return certificates;
        } catch (final IOException | CertificateException e) {
            LOGGER.error("Could not read certificates from file {}", filePath, e);

            return emptyList();
        }
    }

    private Stream<Path> listCertificateFilesByCaPath(final String caPath) {
        final URI classpathUri = toClasspathResourceUri(caPath);
        final var resolvedPath = classpathUri != null ? Paths.get(classpathUri) : Paths.get(caPath);

        if (resolvedPath.toFile().isDirectory()) {
            return listPemFilesInDirectory(resolvedPath);
        }

        return Stream.of(resolvedPath);
    }

    private URI toClasspathResourceUri(final String caPath) {
        try {
            final var classpathUrl = this.getClass().getClassLoader().getResource(caPath);

            return classpathUrl != null ? classpathUrl.toURI() : null;
        } catch (final URISyntaxException e) {
            LOGGER.error("Could not get URI of classpath resource {}", caPath, e);

            return null;
        }
    }

    private static Stream<Path> listPemFilesInDirectory(final Path directory) {
        final var pemFiles = directory.toFile().listFiles((FileFilter) new SuffixFileFilter(PEM_EXTENSION));

        return arrayToStream(pemFiles)
                .map(File::toPath);
    }

    private static <T> Stream<T> arrayToStream(final T[] array) {
        return array != null ? Stream.of(array) : Stream.empty();
    }
}
