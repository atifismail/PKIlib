package com.dreamsecurity.ca.x509.core.extension;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;


/**
 * Issuer Alternative certificate extension
 * @author dream
 *
 *  otherName                     = 0;
 *	rfc822Name                    = 1;
 *	dNSName                       = 2;
 *	x400Address                   = 3;
 *	directoryName                 = 4;
 *	ediPartyName                  = 5;
 *	uniformResourceIdentifier     = 6;
 *	iPAddress                     = 7;
 *	registeredID                  = 8;
 */
public class IssuerAltNameType {

	private Boolean critical;	
	private GeneralNamesBuilder nameBuilder;
	
    public static final int otherName                     = 0;
    public static final int rfc822Name                    = 1;
    public static final int dNSName                       = 2;
    public static final int x400Address                   = 3;
    public static final int directoryName                 = 4;
    public static final int ediPartyName                  = 5;
    public static final int uniformResourceIdentifier     = 6;
    public static final int iPAddress                     = 7;
    public static final int registeredID                  = 8;
	
	public IssuerAltNameType() {
		this.setCritical(false);
		nameBuilder = new GeneralNamesBuilder();
	}
		
	public void addAltName(String name, int tag) {
		nameBuilder.addName(new GeneralName(tag, name));	
	}
	
	public GeneralNames compile() {
		return nameBuilder.build();
	}

	public Boolean isCritical() {
		return critical;
	}

	public void setCritical(Boolean critical) {
		this.critical = critical;
	}
}
