package com.dreamsecurity.ca.x509.core.extension;

import java.math.BigInteger;

import org.bouncycastle.asn1.x509.PolicyConstraints;

/**
 * Policy restrictions PolicyConstraints ::= SEQUENCE { requireExplicitPolicy
 * [0] SkipCerts OPTIONAL, inhibitPolicyMapping [1] SkipCerts OPTIONAL }
 */

public class PolicyConstraintsType {

	private Boolean critical;
	private BigInteger requireExplicitPolicy; // indicates the number of
												// additional certificates
	private BigInteger inhibitPolicyMapping; // number of application support

	public PolicyConstraintsType() {
		this.critical = false;
	}

	public void addRequireExplicitPolicy(BigInteger value) {
		requireExplicitPolicy = value;
	}

	public void addInhibitPolicyMapping(BigInteger value) {
		inhibitPolicyMapping = value;
	}

	public PolicyConstraints compile() {

		/*ASN1EncodableVector pcVector = new ASN1EncodableVector();
		pcVector.add(new DERTaggedObject(false, 0, new ASN1Integer(requireExplicitPolicy)));
		pcVector.add(new DERTaggedObject(false, 1, new ASN1Integer(inhibitPolicyMapping)));
		*/
		return new PolicyConstraints(this.requireExplicitPolicy, this.inhibitPolicyMapping);
	}

	public Boolean isCritical() {
		return critical;
	}

	public void setCritical(Boolean critical) {
		this.critical = critical;
	}
}