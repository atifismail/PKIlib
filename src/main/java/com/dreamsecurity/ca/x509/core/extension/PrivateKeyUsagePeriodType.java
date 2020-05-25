package com.dreamsecurity.ca.x509.core.extension;

import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;

/**
 * Private key usage certificate extension 
 * @author dream
 *
 */
public class PrivateKeyUsagePeriodType {

	private Date notBefore;
	private Date notAfter;
	private Boolean critical;
	
	public PrivateKeyUsagePeriod compile() {
			
		ASN1GeneralizedTime notBeforeGT = new ASN1GeneralizedTime(notBefore);
		ASN1GeneralizedTime notAfterGT = new ASN1GeneralizedTime(notAfter);
		
		DERTaggedObject dtoNotBefterKey = new DERTaggedObject(false, 0,
				notBeforeGT);
		DERTaggedObject dtoNotAfterKey = new DERTaggedObject(false, 1,
				notAfterGT);

		ASN1EncodableVector aevPriKeyUsagePeriod = new ASN1EncodableVector();
		aevPriKeyUsagePeriod.add(dtoNotBefterKey);
		aevPriKeyUsagePeriod.add(dtoNotAfterKey);
		return PrivateKeyUsagePeriod
				.getInstance(new DERSequence(aevPriKeyUsagePeriod));
		
	}
	
	public PrivateKeyUsagePeriodType() {
		critical = false;
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}

	public Date getNotAfter() {
		return notAfter;
	}

	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}

	public Boolean isCritical() {
		return critical;
	}

	public void setCritical(Boolean critical) {
		this.critical = critical;
	}
	
	
}
