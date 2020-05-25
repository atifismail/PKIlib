package com.dreamsecurity.ca.x509.core.extension;

import java.util.Hashtable;

import org.bouncycastle.asn1.x509.PolicyMappings;

/**
 * Policy mapping extensions exist only in cross-certificates, indicating the mutual mapping of CP levels between different CA domains.
 * 
 * PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
 * issuerDomainPolicy CertPolicyId, subjectDomainPolicy CertPolicyId }
 */

public class PolicyMappingType {

	private Boolean critical;
	private Hashtable<String, String> policyMap = new Hashtable<String,String>();
	
	public PolicyMappingType() {
		this.critical = false;
	}
	
	public void addPolicyMapping(String policy1, String policy2) {				
		policyMap.put(policy1, policy2);	
	}

	@SuppressWarnings("deprecation")
	public PolicyMappings compile() {
		return new PolicyMappings(policyMap);
	}
	
	public Boolean isCritical() {
		return critical;
	}
	public void setCritical(Boolean critical) {
		this.critical = critical;
	}
	
	
	
}
