package com.dreamsecurity.ca.x509.core.extension;

import java.util.Date;

import org.bouncycastle.asn1.DERGeneralizedTime;

/**
 * Expired Certificate, CRL extension
 * @author dream
 *
 */
public class ExpiredCertsOnCRLType {

	private Date time;
	
	private Boolean critical;
	
	public DERGeneralizedTime compile() {
		
		return new DERGeneralizedTime(time);
		
	}
	
	public ExpiredCertsOnCRLType(Date time) {
		this.time = time;
		critical = false;
	}

	public Date getTime() {
		return time;
	}

	public void setTime(Date time) {
		this.time = time;
	}

	public Boolean isCritical() {
		return critical;
	}

	public void setCritical(Boolean critical) {
		this.critical = critical;
	}	
	
}
