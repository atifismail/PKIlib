package com.dreamsecurity.ca.x509.core.extension;

import org.bouncycastle.asn1.x509.KeyUsage;

/**
 * Certificate KeyUsage
 * @author dream
 *
 */
public class KeyUsageType {

	private Boolean digitalSignature;
	private Boolean nonRepudiation;
	private Boolean keyEncipherment;
	private Boolean dataEncipherment;
	private Boolean keyAgreement;
	private Boolean keyCertSign;
	private Boolean crlSign;
	private Boolean encipherOnly;
	private Boolean decipherOnly;
	private Boolean critical;

	public KeyUsageType() {
		digitalSignature = nonRepudiation = keyEncipherment = dataEncipherment = keyAgreement = keyCertSign = crlSign = encipherOnly = decipherOnly = false;

		critical = true;
	}

	public KeyUsage compile() {
		int keyUsageValue = 0;

		if (isDigitalSignature()) {
			keyUsageValue |= KeyUsage.digitalSignature;
		}
		if (isNonRepudiation()) {
			keyUsageValue |= KeyUsage.nonRepudiation;
		}
		if (isKeyEncipherment()) {
			keyUsageValue |= KeyUsage.keyEncipherment;
		}
		if (isDataEncipherment()) {
			keyUsageValue |= KeyUsage.dataEncipherment;
		}
		if (isKeyAgreement()) {
			keyUsageValue |= KeyUsage.keyAgreement;
		}
		if (isKeyCertSign()) {
			keyUsageValue |= KeyUsage.keyCertSign;
		}
		if (isCRLSign()) {
			keyUsageValue |= KeyUsage.cRLSign;
		}
		if (isEncipherOnly()) {
			keyUsageValue |= KeyUsage.encipherOnly;
		}
		if (isDecipherOnly()) {
			keyUsageValue |= KeyUsage.decipherOnly;
		}

		return new KeyUsage(keyUsageValue);
	}

	public Boolean isDigitalSignature() {
		return digitalSignature;
	}

	public void setDigitalSignature(Boolean value) {
		this.digitalSignature = value;
	}

	public Boolean isNonRepudiation() {
		return nonRepudiation;
	}

	public void setNonRepudiation(Boolean value) {
		this.nonRepudiation = value;
	}

	public Boolean isKeyEncipherment() {
		return keyEncipherment;
	}

	public void setKeyEncipherment(Boolean value) {
		this.keyEncipherment = value;
	}

	public Boolean isDataEncipherment() {
		return dataEncipherment;
	}

	public void setDataEncipherment(Boolean value) {
		this.dataEncipherment = value;
	}

	public Boolean isKeyAgreement() {
		return keyAgreement;
	}

	public void setKeyAgreement(Boolean value) {
		this.keyAgreement = value;
	}

	public Boolean isKeyCertSign() {
		return keyCertSign;
	}

	public void setKeyCertSign(Boolean value) {
		this.keyCertSign = value;
	}

	public Boolean isCRLSign() {
		return crlSign;
	}

	public void setCRLSign(Boolean value) {
		this.crlSign = value;
	}

	public Boolean isEncipherOnly() {
		return encipherOnly;
	}

	public void setEncipherOnly(Boolean value) {
		this.encipherOnly = value;
	}

	public Boolean isDecipherOnly() {
		return decipherOnly;
	}

	public void setDecipherOnly(Boolean value) {
		this.decipherOnly = value;
	}

	public boolean isCritical() {
		return this.critical;
	}

	public void setCritical(Boolean value) {
		this.critical = value;
	}
}