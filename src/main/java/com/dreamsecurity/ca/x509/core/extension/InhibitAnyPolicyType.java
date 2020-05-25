package com.dreamsecurity.ca.x509.core.extension;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;

/**
 * Any strategy is prohibited:
 * The value of the extension is an integer N, and N means: in the certificate path, the N certificates under this certificate can carry the certificate of Any-Policy.
 * (The certificate under N+1 cannot have Any-policy)
 * 
 * id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::= { id-ce 54 }
 * 
 * InhibitAnyPolicy ::= SkipCerts
 * 
 * SkipCerts ::= INTEGER (0..MAX)
 */

public class InhibitAnyPolicyType {
	
	private Boolean critical;
	private BigInteger inhibitAnyPolicy;
	
	public InhibitAnyPolicyType() {
		this.critical = false;
	}
	
	public void setValue(BigInteger i) {
		this.inhibitAnyPolicy = i;
	}
	
	public ASN1Integer compile() {
		return new ASN1Integer(inhibitAnyPolicy);
	}
	
	public Boolean isCritical() {
		return critical;
	}


	public void setCritical(Boolean critical) {
		this.critical = critical;
	}
}