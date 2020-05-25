package com.dreamsecurity.ca.x509.factory;

import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.dreamsecurity.ca.x509.core.PKCS10RequestInfo;
import com.dreamsecurity.ca.x509.core.policy.CertificatePolicy;

/**
 * Generate X.509 Certificate
 * @author dream
 *
 */
public class CertificateFactory {

	private static final Logger logger = LogManager.getLogger(CertificateFactory.class);

	private CertificatePolicy certPolicy;

	/**
	 * Set X.509 Certificate policy
	 * @param certificatePolicy Set Certificate policy
	 */
	public CertificateFactory(CertificatePolicy certificatePolicy) {
		this.certPolicy = certificatePolicy;
	}

	/**
	 * Issue X.509 Certificate
	 * @param serialNumber Certificate serial number
	 * @param issuerDNStr Certificate Issuer DN
	 * @param issuerPriKey Certificate signing private key
	 * @param encodedP10 Byte encoded PKCS10CertificationRequest
	 * @return
	 */
	public X509Certificate issueCertificate(BigInteger serialNumber, String issuerDNStr, PrivateKey issuerPriKey,
			byte[] encodedP10) {

		X509Certificate cert = null;
		X500Principal issuerDN = new X500Principal(issuerDNStr);

		PKCS10RequestInfo reqInfo = new PKCS10RequestInfo();
		reqInfo.init(encodedP10);

		if (!reqInfo.isValid()) {
			throw new InvalidParameterException("Certificate request cannot be verified");
		}

		// TODO check for request extensions				
		
		// issue certificate
		cert = genearateCert(issuerDN, serialNumber, new X500Principal(reqInfo.getDn()), reqInfo.getPublicKey(),
				issuerPriKey);

		return cert;
	}

	/**
	 * Issue X.509 Certificate
	 * @param serialNumber Certificate serial number
	 * @param issuerDNStr Certificate Issuer DN
	 * @param subjectDNStr Certificate Subject DN
	 * @param subjectPubKey Certificate Subject public key
	 * @param issuerPriKey Certificate signing key
	 * @return
	 */
	public X509Certificate issueCertificate(BigInteger serialNumber, String issuerDNStr, String subjectDNStr,
			PublicKey subjectPubKey, PrivateKey issuerPriKey) {

		X509Certificate cert = null;

		X500Principal issuerDN = new X500Principal(issuerDNStr);
		X500Principal subjectDN = new X500Principal(subjectDNStr);

		// issue certificate
		cert = genearateCert(issuerDN, serialNumber, subjectDN, subjectPubKey, issuerPriKey);

		return cert;
	}

	private X509Certificate genearateCert(X500Principal issuerDN, BigInteger serialNumber, X500Principal subjectDN,
			PublicKey subjectPubKey, PrivateKey issuerPriKey) {

		X509v3CertificateBuilder x509Builder = new JcaX509v3CertificateBuilder(issuerDN, serialNumber,
				certPolicy.getValidity().getNotBefore(), certPolicy.getValidity().getNotAfter(), subjectDN,
				subjectPubKey);

		try {
			// basic constraints
			if (certPolicy.getBasicConstraints() != null) {
				x509Builder.addExtension(Extension.basicConstraints, certPolicy.getBasicConstraints().isCritical(),
						certPolicy.getBasicConstraints().compile());
			}

			// key id
			if (certPolicy.getAuthKeyId() != null) {
				x509Builder.addExtension(Extension.authorityKeyIdentifier, certPolicy.getAuthKeyId().isCritical(),
						certPolicy.getAuthKeyId().compile());
			}
			if (certPolicy.getSubjectKeyId() != null) {
				x509Builder.addExtension(Extension.subjectKeyIdentifier, certPolicy.getSubjectKeyId().isCritical(),
						certPolicy.getSubjectKeyId().compile());
			}

			// key usage
			if (certPolicy.getKeyUsageType() != null) {
				x509Builder.addExtension(Extension.keyUsage, certPolicy.getKeyUsageType().isCritical(),
						certPolicy.getKeyUsageType().compile());
			}

			// ext key usage
			if (certPolicy.getExtKeyUsageType() != null) {
				x509Builder.addExtension(Extension.extendedKeyUsage, certPolicy.getExtKeyUsageType().isCritical(),
						certPolicy.getExtKeyUsageType().compile());
			}

			// aia
			if (certPolicy.getAuthorityInformationAccessType() != null) {
				x509Builder.addExtension(Extension.authorityInfoAccess,
						certPolicy.getAuthorityInformationAccessType().isCritical(),
						certPolicy.getAuthorityInformationAccessType().compile());
			}

			// cert policies
			if (certPolicy.getCertPolicy() != null) {
				x509Builder.addExtension(Extension.certificatePolicies, certPolicy.getCertPolicy().isCritical(),
						certPolicy.getCertPolicy().compile());
			}

			// crl dp
			if (certPolicy.getCrlDistributionPointsType() != null) {
				x509Builder.addExtension(Extension.cRLDistributionPoints,
						certPolicy.getCrlDistributionPointsType().isCritical(),
						certPolicy.getCrlDistributionPointsType().compile());
			}

			// inhibit any policy
			if (certPolicy.getAnyPolicyType() != null) {
				x509Builder.addExtension(Extension.inhibitAnyPolicy, certPolicy.getAnyPolicyType().isCritical(),
						certPolicy.getAnyPolicyType().compile());
			}

			// issuer alt name
			if (certPolicy.getIssuerAltNameType() != null) {
				x509Builder.addExtension(Extension.issuerAlternativeName,
						certPolicy.getIssuerAltNameType().isCritical(), certPolicy.getIssuerAltNameType().compile());
			}

			// name constraints
			if (certPolicy.getNameConstraintsType() != null) {
				x509Builder.addExtension(Extension.nameConstraints, certPolicy.getNameConstraintsType().isCritical(),
						certPolicy.getNameConstraintsType().compile());
			}

			// policy constraits
			if (certPolicy.getPolicyConstraintsType() != null) {
				x509Builder.addExtension(Extension.policyConstraints,
						certPolicy.getPolicyConstraintsType().isCritical(),
						certPolicy.getPolicyConstraintsType().compile());
			}

			// policy mapping
			if (certPolicy.getPolicyMappingType() != null) {
				x509Builder.addExtension(Extension.policyMappings, certPolicy.getPolicyMappingType().isCritical(),
						certPolicy.getPolicyMappingType().compile());
			}

			// private key usage period
			if (certPolicy.getPrivateKeyUsagePeriodType() != null) {
				x509Builder.addExtension(Extension.privateKeyUsagePeriod,
						certPolicy.getPrivateKeyUsagePeriodType().isCritical(),
						certPolicy.getPrivateKeyUsagePeriodType().compile());
			}

			// subject alt name
			if (certPolicy.getSubjectAltNameType() != null) {
				x509Builder.addExtension(Extension.subjectAlternativeName,
						certPolicy.getSubjectAltNameType().isCritical(), certPolicy.getSubjectAltNameType().compile());
			}

			// subject info access
			if (certPolicy.getSubjectInformationAccessType() != null) {
				x509Builder.addExtension(Extension.subjectInfoAccess,
						certPolicy.getSubjectInformationAccessType().isCritical(),
						certPolicy.getSubjectInformationAccessType().compile());
			}

			// subject dir attribute type
			if (certPolicy.getSubjectDirectoryAttributesType() != null) {
				x509Builder.addExtension(Extension.subjectDirectoryAttributes,
						certPolicy.getSubjectDirectoryAttributesType().isCritical(),
						certPolicy.getSubjectDirectoryAttributesType().compile());
			}

			// freshest crl
			if (certPolicy.getFreshestCRLType() != null) {
				x509Builder.addExtension(Extension.freshestCRL, false, certPolicy.getFreshestCRLType().compile());
			}

			/////////// ICAO-PKI CSCA ////////

			// DS - doc type extension
			if (certPolicy.getDocTypeList() != null) {
				x509Builder.addExtension(ICAOObjectIdentifiers.id_icao_documentTypeList,
						certPolicy.getDocTypeList().isCritical(), certPolicy.getDocTypeList().compile());
			}

			// NameChange extension link certificate/CSCA certificate
			if (certPolicy.getNameChangeType() != null) {
				x509Builder.addExtension(ICAOObjectIdentifiers.id_icao_extensions_namechangekeyrollover,
						certPolicy.getNameChangeType().isCritical(), certPolicy.getNameChangeType().compile());
			}
		} catch (CertIOException e) {
			logger.error("Error in adding certificate extention: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		/////////////////////////////////

		/// content signer
		ContentSigner signer = null;
		try {
			signer = new JcaContentSignerBuilder(certPolicy.getSigningAlgorithm()).build(issuerPriKey);
		} catch (OperatorCreationException e) {
			logger.error("Error in building ContentSigner: " + e.getMessage());
			e.printStackTrace();
		}

		X509CertificateHolder holder = x509Builder.build(signer);

		// convert to JRE certificate
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		converter.setProvider(new BouncyCastleProvider());

		X509Certificate cert = null;

		try {
			cert = converter.getCertificate(holder);
		} catch (CertificateException e) {
			logger.error("Error in getting X509Certificate from X509CertificateHolder: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		return cert;
	}

	public void setCertificatePolicy(CertificatePolicy cp) {
		this.certPolicy = cp;
	}

	public CertificatePolicy getCerificatePolicy() {
		return this.certPolicy;
	}

}
