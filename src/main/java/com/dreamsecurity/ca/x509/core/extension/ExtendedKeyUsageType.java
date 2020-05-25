package com.dreamsecurity.ca.x509.core.extension;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;

/**
 * Enhanced Key Usage The extendedKeyUsage object.
 * 
 * <pre>
 *      extendedKeyUsage ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 * </pre>
 * * asn1ExtKeyUsage.add(KeyPurposeId.id_kp_dvcs);
 * asn1ExtKeyUsage.add(KeyPurposeId.id_kp_sbgpCertAAServerAuth);
 * asn1ExtKeyUsage.add(KeyPurposeId.id_kp_scvp_responder);
 * asn1ExtKeyUsage.add(KeyPurposeId.id_kp_eapOverPPP);
 * asn1ExtKeyUsage.add(KeyPurposeId.id_kp_eapOverLAN);
 * asn1ExtKeyUsage.add(KeyPurposeId.id_kp_scvpServer);
 * asn1ExtKeyUsage.add(KeyPurposeId.id_kp_scvpClient);
 * asn1ExtKeyUsage.add(KeyPurposeId.id_kp_ipsecIKE);
 * asn1ExtKeyUsage.add(KeyPurposeId.id_kp_capwapAC);
 * asn1ExtKeyUsage.add(KeyPurposeId.id_kp_capwapWTP);
 */

public class ExtendedKeyUsageType {    
	    
	private Boolean critical;
	private List<KeyPurposeId> asn1ExtKeyUsage;
	
	public ExtendedKeyUsageType() {
		this.setCritical(false);
		asn1ExtKeyUsage = new ArrayList<KeyPurposeId>();
	}
	
	public void addExtKeyUsage(KeyPurposeId kpId) {
		asn1ExtKeyUsage.add(kpId);
	}
	
	public ExtendedKeyUsage compile() {
		return new ExtendedKeyUsage( asn1ExtKeyUsage.toArray(new KeyPurposeId[asn1ExtKeyUsage.size()]));

	}

	public Boolean isCritical() {
		return critical;
	}

	public void setCritical(Boolean critical) {
		this.critical = critical;
	}	
}
