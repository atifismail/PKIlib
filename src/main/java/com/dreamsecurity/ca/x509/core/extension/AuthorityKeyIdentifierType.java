package com.dreamsecurity.ca.x509.core.extension;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import com.dreamsecurity.ca.util.Constants;

/**
 * Certificate Authority Key Identifier extension 
 * @author dream
 *
 */
public class AuthorityKeyIdentifierType {

	private static final Logger logger = LogManager.getLogger(AuthorityKeyIdentifierType.class);
	
	private byte[] issuerPublicKey;
	private String issuerDN;
	private BigInteger issuerSerialNumber;
	private Boolean isCritical;
	
	public AuthorityKeyIdentifierType(byte[] issuerPublicKey) {
		isCritical = false;
		
		this.issuerPublicKey = issuerPublicKey;
	}
	
	public AuthorityKeyIdentifierType(byte[] issuerPublicKey, String issuerDN, BigInteger issuerSerialNumber) {
		isCritical = false;
		
		this.issuerPublicKey = issuerPublicKey;
		this.issuerDN = issuerDN;
		this.issuerSerialNumber = issuerSerialNumber;
	}	
	
	public AuthorityKeyIdentifier compile() {
		AuthorityKeyIdentifier ki = null;
		try {
			if(issuerDN != null && issuerSerialNumber !=null) {
				ki = new AuthorityKeyIdentifier(
						MessageDigest.getInstance(Constants.HashAlgo.sha1.getValue(), Constants.bc_provider).digest(issuerPublicKey), 
						new GeneralNames(new GeneralName(new X500Name(issuerDN))), issuerSerialNumber);
			} else {
				ki = new AuthorityKeyIdentifier(
						MessageDigest.getInstance(Constants.HashAlgo.sha1.getValue(), Constants.bc_provider).digest(issuerPublicKey));
			}			
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			logger.error("Error in compiling. " + e.getMessage());
			e.printStackTrace();
			return null;
		}		
		return ki;
	}
	
	public byte[] getKeyIdentifier() {
		return issuerPublicKey;
	}

	public void setKeyIdentifier(byte[] keyIdentifier) {
		this.issuerPublicKey = keyIdentifier;
	}

	public String getAuthCertIssuer() {
		return issuerDN;
	}

	public void setAuthCertIssuer(String authCertIssuer) {
		this.issuerDN = authCertIssuer;
	}

	public BigInteger getAuthCertSerialNumber() {
		return issuerSerialNumber;
	}

	public void setAuthCertSerialNumber(BigInteger authCertSerialNumber) {
		this.issuerSerialNumber = authCertSerialNumber;
	}

	public Boolean isCritical() {
		return isCritical;
	}

	public void setCritical(Boolean isCritical) {
		this.isCritical = isCritical;
	}
}
