package com.dreamsecurity.ca.cvc.bc.factory;

import java.security.PrivateKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.eac.CVCertificate;
import org.bouncycastle.asn1.eac.PackedDate;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;
import org.bouncycastle.eac.EACCertificateBuilder;
import org.bouncycastle.eac.EACCertificateHolder;
import org.bouncycastle.eac.EACException;
import org.bouncycastle.eac.jcajce.JcaPublicKeyConverter;
import org.bouncycastle.eac.operator.EACSigner;
import org.bouncycastle.eac.operator.jcajce.JcaEACSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import com.dreamsecurity.ca.cvc.bc.policy.CVCertificatePolicy;

/**
 * Generate CVC certificates
 * 
 * @author dream 
 */
public class CVCertificateFactory {

	private static final Logger logger = LogManager.getLogger(CVCertificateFactory.class);

	private CVCertificatePolicy certPolicy;

	/**
	 * Set CVC certificate policy
	 * @param cp Certificate policy defining the various properties of certificate
	 */
	public CVCertificateFactory(CVCertificatePolicy cp) {
		this.certPolicy = cp;
	}

	/**
	 * Issue CV Certificate
	 * @param privateKey Signing Private key
	 * @param SigningAlgo Signing Algorithm
	 * @return
	 */
	public CVCertificate issueCVCert(PrivateKey privateKey, String SigningAlgo) {

		JcaEACSignerBuilder signerBuilder = new JcaEACSignerBuilder().setProvider(new BouncyCastleProvider());

		EACSigner signer = null;
		try {
			signer = signerBuilder.build(SigningAlgo, privateKey);
		} catch (OperatorCreationException e) {
			logger.error("Error in building EACSigner: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		// convert public key
		PublicKeyDataObject pubKeyDO = new JcaPublicKeyConverter().getPublicKeyDataObject(signer.getUsageIdentifier(),
				certPolicy.getPublicKey());

		EACCertificateBuilder certificateBuilder = new EACCertificateBuilder(
				certPolicy.getCertificationAuthorityReference(), pubKeyDO, certPolicy.getCertificateHolderReference(),
				certPolicy.getCertificateHolderAuthorization(), new PackedDate(certPolicy.getValidity().getNotBefore()),
				new PackedDate(certPolicy.getValidity().getNotAfter()));

		EACCertificateHolder eacCertificateHolder = null;
		try {
			eacCertificateHolder = certificateBuilder.build(signer);
		} catch (EACException e) {
			logger.error("Error in building certificate: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		return eacCertificateHolder.toASN1Structure();
	}

	public CVCertificatePolicy getCertPolicy() {
		return certPolicy;
	}

	public void setCertPolicy(CVCertificatePolicy certPolicy) {
		this.certPolicy = certPolicy;
	}

}
