package com.dreamsecurity.ca.cvc.ejbca.factory;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;

import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

import com.dreamsecurity.ca.cvc.ejbca.policy.CVCertificatePolicy;
import com.dreamsecurity.ca.util.Constants;

/**
 * Generate CV Certificates
 * @author dream
 *
 */
public class CVCertificateFactory {

	private CVCertificatePolicy certPolicy;

	/**
	 * Set certificate policy
	 * @param cp Certificate policy
	 */
	public CVCertificateFactory(CVCertificatePolicy cp) {
		this.certPolicy = cp;
	}

	/**
	 * Converts DER encoded bytes to instance of CVCertificate
	 * @param derEncodedCVCert byte array of DER encoded CVCertificate
	 * @return
	 */
	public CVCertificate getInstance(byte[] derEncodedCVCert) {
		
		CVCertificate cert = null;
		
		try {
			CertificateParser.parseCertificate(derEncodedCVCert);			
		} catch (ParseException | ConstructionException e) {
			System.err.println("Error in parsing encoded certificate: " + e.getMessage());
			e.printStackTrace();
		}
		
		return cert;
	}

	/**
	 * Issue CVCertificate using certificate policy
	 * @param signingPrivateKey Signer private key
	 * @return
	 */
	public CVCertificate issueCVCert(PrivateKey signingPrivateKey) {

		CVCertificate cert = null;

		try {
			cert = CertificateGenerator.createCertificate(this.certPolicy.getPublicKey(), signingPrivateKey,
					this.certPolicy.getSigningAlgorithm(), this.certPolicy.getCertificationAuthorityReference(),
					this.certPolicy.getCertificateHolderReference(), this.certPolicy.getAuthRole(),
					this.certPolicy.getAccessRights(), this.certPolicy.getValidity().getNotBefore(),
					this.certPolicy.getValidity().getNotAfter(), this.certPolicy.getExtensions(), Constants.bc_provider);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException
				| ConstructionException | IOException e) {
			System.err.println("Error in creating CVCertificate: " + e.getMessage());
			e.printStackTrace();
		}

		return cert;
	}

	public CVCertificatePolicy getCertPolicy() {
		return certPolicy;
	}

	public void setCertPolicy(CVCertificatePolicy certPolicy) {
		this.certPolicy = certPolicy;
	}

}
