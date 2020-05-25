package com.dreamsecurity.ca.x509.core.extension;

import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.ReasonFlags;

/**
 * The issuing distribution point is a critical CRL extension that identifies
 * the CRL distribution point and scope for a particular CRL, and it indicates
 * whether the CRL covers revocation for end entity certificates only, CA
 * certificates only, attribute certificates only, or a limited set of reason
 * codes. Although the extension is critical, conforming implementations are not
 * required to support this extension. However, implementations that do not
 * support this extension MUST either treat the status of any certificate not
 * listed on this CRL as unknown or locate another CRL that does not contain any
 * unrecognized critical extensions.
 * 
 * id-ce-issuingDistributionPoint OBJECT IDENTIFIER ::= { id-ce 28 }
 *
 * IssuingDistributionPoint ::= SEQUENCE { distributionPoint [0]
 * DistributionPointName OPTIONAL, onlyContainsUserCerts [1] BOOLEAN DEFAULT
 * FALSE, onlyContainsCACerts [2] BOOLEAN DEFAULT FALSE, onlySomeReasons [3]
 * ReasonFlags OPTIONAL, indirectCRL [4] BOOLEAN DEFAULT FALSE,
 * onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
 *
 * -- at most one of onlyContainsUserCerts, onlyContainsCACerts, -- and
 * onlyContainsAttributeCerts may be set to TRUE.
 */

public class IssuingDistributionPointType {

	Integer type;
	String value;

	ReasonFlags reason;
	boolean onlyUserCerts;
	boolean onlyCaCerts;
	boolean indirectCRL;
	boolean onlyAttrCerts;

	private Boolean critical;

	public static final int otherName = 0;
	public static final int rfc822Name = 1;
	public static final int dNSName = 2;
	public static final int x400Address = 3;
	public static final int directoryName = 4;
	public static final int ediPartyName = 5;
	public static final int uniformResourceIdentifier = 6;
	public static final int iPAddress = 7;
	public static final int registeredID = 8;

	/* reason flags */
	public static final int unused = (1 << 7);
	public static final int keyCompromise = (1 << 6);
	public static final int cACompromise = (1 << 5);
	public static final int affiliationChanged = (1 << 4);
	public static final int superseded = (1 << 3);
	public static final int cessationOfOperation = (1 << 2);
	public static final int certificateHold = (1 << 1);
	public static final int privilegeWithdrawn = (1 << 0);
	public static final int aACompromise = (1 << 15);

	public IssuingDistributionPointType() {
		this.critical = true;

		onlyAttrCerts = false;
		onlyCaCerts = false;
		onlyUserCerts = false;
		indirectCRL = false;
	}
	
	public void addIssuingDisPoint(String dpName, int type, ReasonFlags reason, boolean indirectCrl, boolean onlyUserCerts,
			boolean onlyCaCerts, boolean onlyAttrCerts) {

		this.type = type;
		this.value = dpName;

		this.reason = reason;

		this.indirectCRL = indirectCrl;
		this.onlyUserCerts = onlyUserCerts;
		this.onlyCaCerts = onlyCaCerts;
		this.onlyAttrCerts = onlyAttrCerts;
	}

	public IssuingDistributionPoint compile() {

		GeneralName gn = null;

		gn = new GeneralName(this.type, this.value);

		GeneralNames gns = new GeneralNames(gn);
		DistributionPointName dpn = new DistributionPointName(gns);

		IssuingDistributionPoint idp = new IssuingDistributionPoint(dpn, this.onlyUserCerts, this.onlyCaCerts,
				this.reason, this.indirectCRL, this.onlyAttrCerts);

		return idp;
	}

	public Integer getType() {
		return type;
	}

	public void setType(Integer type) {
		this.type = type;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	public ReasonFlags getReason() {
		return reason;
	}

	public void setReason(ReasonFlags reason) {
		this.reason = reason;
	}

	public boolean isOnlyUserCerts() {
		return onlyUserCerts;
	}

	public void setOnlyUserCerts(boolean onlyUserCerts) {
		this.onlyUserCerts = onlyUserCerts;
	}

	public boolean isOnlyCaCerts() {
		return onlyCaCerts;
	}

	public void setOnlyCaCerts(boolean onlyCaCerts) {
		this.onlyCaCerts = onlyCaCerts;
	}

	public boolean isIndirectCRL() {
		return indirectCRL;
	}

	public void setIndirectCRL(boolean indirectCRL) {
		this.indirectCRL = indirectCRL;
	}

	public boolean isOnlyAttrCerts() {
		return onlyAttrCerts;
	}

	public void setOnlyAttrCerts(boolean onlyAttrCerts) {
		this.onlyAttrCerts = onlyAttrCerts;
	}

	public Boolean isCritical() {
		return critical;
	}

	public void setCritical(Boolean critical) {
		this.critical = critical;
	}
}
