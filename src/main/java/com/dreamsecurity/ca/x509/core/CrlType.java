package com.dreamsecurity.ca.x509.core;

import java.math.BigInteger;
import java.util.Date;

/**
 * Utility class defining properties for CRL entry
 * @author dream
 *
 */
public class CrlType {

	private BigInteger certSerialNo;
	private int reason;
	private Date revocationDate;

	public CrlType(BigInteger certSerialNo, int reason, Date revokeDate) {
		this.certSerialNo = certSerialNo;
		this.reason = reason;
		this.revocationDate = revokeDate;
	}
	
	public BigInteger getCertSerialNo() {
		return certSerialNo;
	}

	public void setCertSerialNo(BigInteger certSerialNo) {
		this.certSerialNo = certSerialNo;
	}

	public int getReason() {
		return reason;
	}

	public void setReason(int reason) {
		this.reason = reason;
	}

	public Date getRevocationDate() {
		return revocationDate;
	}

	public void setRevocationDate(Date revocationDate) {
		this.revocationDate = revocationDate;
	}
}
