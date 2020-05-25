package com.dreamsecurity.ca.cvc.bc.policy;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import org.bouncycastle.asn1.eac.CertificateHolderReference;
import org.bouncycastle.asn1.eac.CertificationAuthorityReference;

import com.dreamsecurity.ca.util.Validity;

/**
 * Certificate policy defines the various properties of CVC certificate 
 * related to certificate body, signing etc
 * @author dream
 *
 */
public class CVCertificatePolicy {

	private Validity validity;
	private String signingAlgorithm;
	
	private CertificationAuthorityReference certificationAuthorityReference;
	private CertificateHolderReference certificateHolderReference;
	private CertificateHolderAuthorization certificateHolderAuthorization;
	private PublicKey publicKey;
	
	public Validity getValidity() {
		return validity;
	}
	public void setValidity(Validity validity) {
		this.validity = validity;
	}
	public String getSigningAlgorithm() {
		return signingAlgorithm;
	}
	public void setSigningAlgorithm(String signingAlgorithm) {
		this.signingAlgorithm = signingAlgorithm;
	}

	public void setCertificationAuthorityReference(String countryCode, String holderMnemonic, String sequenceNumber) {
		this.certificationAuthorityReference = new CertificationAuthorityReference(countryCode, holderMnemonic,
				sequenceNumber);
	}

	public CertificationAuthorityReference getCertificationAuthorityReference() {
		return this.certificationAuthorityReference;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public PublicKey getPublicKey() {
		return this.publicKey;
	}

	public void setCertificateHolderReference(String countryCode, String holderMnemonic, String sequenceNumber) {
		this.certificateHolderReference = new CertificateHolderReference(countryCode, holderMnemonic, sequenceNumber);
	}
	
	public CertificateHolderReference getCertificateHolderReference() {
		return this.certificateHolderReference;
	}

	public void setCertificateHolderAuthorization(ASN1ObjectIdentifier EACTags, int roleAndRights) throws IOException {
		this.certificateHolderAuthorization = new CertificateHolderAuthorization(EACTags, roleAndRights);
	}
	
	public CertificateHolderAuthorization getCertificateHolderAuthorization() {
		return this.certificateHolderAuthorization;
	}
}
