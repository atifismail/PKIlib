package com.dreamsecurity.ca.x509.core.extension;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERNull;

/*
 *  
 *   
 */
/**
 * ICAO Link/CSCA certificate name change extension
 * 
 * id-icao-mrtd-security-extensions-nameChange = 2.23.136.1.1.6.1
 * 
 * @author dream
 */
public class NameChangeType {

	private Boolean critical;
	
	public NameChangeType() {
		this.critical = false;
	}

	public Boolean isCritical() {
		return critical;
	}

	public void setCritical(Boolean critical) {
		this.critical = critical;
	}

	public ASN1Encodable compile() {
		return DERNull.INSTANCE;
	}
	
}
