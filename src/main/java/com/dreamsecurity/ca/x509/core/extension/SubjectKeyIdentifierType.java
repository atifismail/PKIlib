package com.dreamsecurity.ca.x509.core.extension;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

import com.dreamsecurity.ca.util.Constants;

/**
 * Subject Key Identifier certificate extension
 * @author dream
 *
 */
public class SubjectKeyIdentifierType {

	private static final Logger logger = LogManager.getLogger(SubjectKeyIdentifierType.class);
	
	private byte[] subjectPublicKey;
	
	private Boolean isCritical;
		
	public SubjectKeyIdentifier compile() {
		try {
			return new SubjectKeyIdentifier(MessageDigest.getInstance(
					Constants.HashAlgo.sha1.getValue(), Constants.bc_provider).digest(subjectPublicKey));
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			logger.error("Error in compiling: " + e.getMessage());
			e.printStackTrace();
		}	
		
		return null;
	}
	
	public SubjectKeyIdentifierType(byte[] subjectPublicKey) {
		isCritical = false;
		
		this.subjectPublicKey = subjectPublicKey;
	}
	
	public byte[] getSubjectPublicKey() {
		return subjectPublicKey;
	}

	public void setSubjectPublicKey(byte[] subjectPublicKey) {
		this.subjectPublicKey = subjectPublicKey;
	}

	public Boolean isCritical() {
		return isCritical;
	}

	public void setCritical(Boolean isCritical) {
		this.isCritical = isCritical;
	}	
}
