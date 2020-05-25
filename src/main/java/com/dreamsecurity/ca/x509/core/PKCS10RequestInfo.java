package com.dreamsecurity.ca.x509.core;

import java.io.IOException;
import java.security.PublicKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;

/**
 * Generate PKCS10/CSR 
 * 
 * @author dream
 *
 */
public class PKCS10RequestInfo {

	private static final Logger logger = LogManager.getLogger(PKCS10RequestInfo.class);
	
	private PublicKey publicKey;
	private String dn;
	private PKCS10CertificationRequest pkcs10Request;

	public PKCS10RequestInfo() {
	}

	/**
	 * Initialize with byte encoded PKCS10 
	 * @param reqBytes
	 * @return
	 */
	public boolean init(byte[] reqBytes) {

		// get object
		PKCS10CertificationRequest request = null;
		try {
			request = new PKCS10CertificationRequest(reqBytes);
		} catch (IOException e) {
			logger.error("Invalid PKCS10CertificateRequest: " + e.getMessage());
			e.printStackTrace();

			return false;
		}

		// get public key
		JcaPEMKeyConverter c = new JcaPEMKeyConverter();

		try {
			this.publicKey = c.getPublicKey(request.getSubjectPublicKeyInfo());
		} catch (PEMException e) {
			logger.error("Error in getting public key from subjectPublicKeyInfo: " + e.getMessage());
			e.printStackTrace();

			return false;
		}

		// get dn
		this.setDn(request.getSubject().toString());

		this.setPkcs10Request(request);

		return true;
	}

	/**
	 * check if request signature is valid
	 * @return
	 */
	public boolean isValid() {
		boolean result = false;
		try {
			result = this.pkcs10Request.isSignatureValid(new JcaContentVerifierProviderBuilder().build(this.publicKey));
		} catch (OperatorCreationException | PKCSException e) {
			logger.error("Error in validating signature: " + e.getMessage());
			e.printStackTrace();
		}		
		
		return result;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public String getDn() {
		return dn;
	}

	public void setDn(String dn) {
		this.dn = dn;
	}

	public PKCS10CertificationRequest getPkcs10Request() {
		return pkcs10Request;
	}

	public void setPkcs10Request(PKCS10CertificationRequest pkcs10Request) {
		this.pkcs10Request = pkcs10Request;
	}

}
