package com.dreamsecurity.ca.x509.factory;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

/**
 * Generate PKCS10 Certificate request
 * @author dream
 *
 */
public class CertificateRequestFactory {

	private static final Logger logger = LogManager.getLogger(CertificateRequestFactory.class);
	
	/**
	 * Issue PKCS10 certificate request 
	 * @param dnStr Certificate Subject DN
	 * @param subjectPubKey Certificate Subject public key
	 * @param signingKey Certificate Signer private key
	 * @param signAlgo Certificate Signing algorithm
	 * @return
	 */
	public PKCS10CertificationRequest createCertRequest(String dnStr, PublicKey subjectPubKey, PrivateKey signingKey,
			String signAlgo) {

		X500Principal subjectDN = new X500Principal(dnStr);

		PKCS10CertificationRequest request = null;
		
			// public key info
			SubjectPublicKeyInfo pubKeyInfo = null;
			try {
				pubKeyInfo = SubjectPublicKeyInfoFactory
						.createSubjectPublicKeyInfo(PublicKeyFactory.createKey(subjectPubKey.getEncoded()));
			} catch (IOException e) {
				logger.error("Error in getting SubjectPublicKeyInfo from subject public key: " + e.getMessage());				
				e.printStackTrace();
				return null;
			}

			// request builder
			PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(
					new X500Name(subjectDN.toString()), pubKeyInfo);

			// content signer
			ContentSigner signer = null;
			try {
				signer = new JcaContentSignerBuilder(signAlgo).build(signingKey);
			} catch (OperatorCreationException e) {
				logger.error("Error in building ContentSigner: " + e.getMessage());
				e.printStackTrace();
				return null;
			}

			request = builder.build(signer);	

		return request;
	}
	
	/**
	 * Convert byte encoded PKCS10CertificationRequest to Object
	 * @param reqBytes
	 * @return
	 */
	public PKCS10CertificationRequest getInstance(byte[] reqBytes) {

		// get object
		PKCS10CertificationRequest request = null;
		try {
			request = new PKCS10CertificationRequest(reqBytes);
		} catch (IOException e) {
			logger.error("Invalid PKCS10CertificateRequest: " + e.getMessage());
			e.printStackTrace();

			return null;
		}

		return request;
	}
}
