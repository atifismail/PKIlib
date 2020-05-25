package com.dreamsecurity.ca.cvc.ejbca.factory;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

/**
 * Generate CVC Certificate request
 * @author dream
 *
 */
public class CVRequestFactory {
	
	/**
	 * Generate CVCAuthenticatedRequest from bytes
	 * @param derEncodedCVRequest DER encoded byte array of CVAuthenticatedRequest
	 * @return
	 */
	public CVCAuthenticatedRequest getInstance(byte[] derEncodedCVRequest) {
		
		CVCAuthenticatedRequest authRequest = null;
		
		try {
			authRequest = (CVCAuthenticatedRequest)CertificateParser.parseCVCObject(derEncodedCVRequest);
		} catch (ParseException | ConstructionException e) {
			System.err.println("Error in parsing CVCAuthenticationRequest: " + e.getMessage());
			e.printStackTrace();
		}
		
		return authRequest;
	}
	
	/**
	 * Issue CVCAuthenticatedRequest
	 * @param holderRef Certificate Holder Reference
	 * @param holderKeyPair Certificate Holder key pair to sign certificate body (inner signature) 
	 * @param signingAlgo inner and outer signature algorithm
	 * @param authORpreviousHolderRef Authority or previous holder reference
	 * @param authORPreviousKeyPair Authority or previous certificate key pair for outer signature
	 * @return
	 */
	public CVCAuthenticatedRequest issueCVCertRequest(HolderReferenceField holderRef, KeyPair holderKeyPair,
			String signingAlgo, CAReferenceField authORpreviousHolderRef, KeyPair authORPreviousKeyPair ) {
		
        CVCertificate request = null;
		try {
			request = CertificateGenerator.createRequest(holderKeyPair, signingAlgo, holderRef);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException
				| ConstructionException | IOException e) {
			System.err.println("Error in creating certificate request: " + e.getMessage());
			e.printStackTrace();
			return null;
		}        

        CVCAuthenticatedRequest authRequest = null;
		try {
			authRequest = CertificateGenerator.createAuthenticatedRequest(request, authORPreviousKeyPair, signingAlgo, authORpreviousHolderRef);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException
				| ConstructionException | IOException e) {
			System.err.println("Error in creating authentication request: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
        
        return authRequest;
	}
	
}
