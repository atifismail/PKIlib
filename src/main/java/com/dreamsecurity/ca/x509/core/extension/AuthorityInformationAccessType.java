package com.dreamsecurity.ca.x509.core.extension;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * Institutional Information Access id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
 * AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription 
 * 
 * AccessDescription ::= SEQUENCE { 
 * accessMethod OBJECT IDENTIFIER, 
 * accessLocation GeneralName } 
 * 
 * id-ad OBJECT IDENTIFIER ::= { id-pkix 48 } 
 * id-ad-caIssuers OBJECT IDENTIFIER ::= {
 * id-ad 2 } id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
 */

public class AuthorityInformationAccessType {

	private Boolean critical;
	private List<AccessDescription> authorityInnfoAccess;
	
	public final static ASN1ObjectIdentifier id_ad_caIssuers = AccessDescription.id_ad_caIssuers;
	public final static ASN1ObjectIdentifier id_ad_ocsp = AccessDescription.id_ad_ocsp;
	public final static ASN1ObjectIdentifier id_ad_caRepository = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.5");
	
	public AuthorityInformationAccessType() {
		this.critical = false;		
		authorityInnfoAccess = new ArrayList<>();		
	}
	
	public void addAIA(String info, ASN1ObjectIdentifier id) {
		AccessDescription caIssuers = new AccessDescription(id,
				new GeneralName(GeneralName.uniformResourceIdentifier, info));
		
		authorityInnfoAccess.add(caIssuers);
	}
	
	public AuthorityInformationAccess compile() {
		return new AuthorityInformationAccess(authorityInnfoAccess.toArray(new AccessDescription[authorityInnfoAccess.size()]));
	}

	public Boolean isCritical() {
		return critical;
	}

	public void setCritical(Boolean critical) {
		this.critical = critical;
	}	
}
