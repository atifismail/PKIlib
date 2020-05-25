package com.dreamsecurity.ca.x509.core.extension;

import java.util.Vector;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;

/**
 * Subject Directory Attributes In principle, you can add information about the Subject,
 * because the OID of the Atrribute Type is used, and then the corresponding value is specified.
 */

public class SubjectDirectoryAttributesType {
	
	// http://asn1.elibel.tm.fr/cgi-bin/oid/display?oid=1.3.6.1.5.5.7.9&action=display
	// PKIX personal data gender
	public static final String genderOidStr = "1.3.6.1.5.5.7.9.4";
	// PKIX personal data dateOfBirth
	public static final String dateOfBirthOidStr = "1.3.6.1.5.5.7.9.1";
	// 2.5.4.20 - id-at-telephoneNumber
	// http://www.alvestrand.no/objectid/2.5.4.html
	public static final String streetAddressOidStr = "2.5.4.9";
	public static final String telephoneNumberOidStr = "2.5.4.20";
	// http://oid.elibel.tm.fr/0.9.2342.19200300.100.1.41
	public static final String mobileTelephoneNumberOidStr = "0.9.2342.19200300.100.1.41";

	private Vector<Attribute> attributes;
	private Boolean critical;
	
	public SubjectDirectoryAttributesType() {
		this.setCritical(false);
		attributes = new Vector<Attribute>();
	}
	
	public void addAttribute(String attrValue, String type)
	{
		Attribute attribute = null;
		attribute = new Attribute(new ASN1ObjectIdentifier(type), 
				new DERSet(new DERPrintableString(attrValue)));				
		attributes.add(attribute);		
	}
	
	public SubjectDirectoryAttributes compile() {
		// Build theme directory properties
		return new SubjectDirectoryAttributes(attributes);
	}

	public Boolean isCritical() {
		return critical;
	}

	public void setCritical(Boolean critical) {
		this.critical = critical;
	}
	
}
