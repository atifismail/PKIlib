package com.dreamsecurity.ca.x509.core.extension;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;

/**
 * Certificate Strategy
 * 
 * certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
 * 
 * PolicyInformation ::= SEQUENCE { policyIdentifier CertPolicyId,
 * policyQualifiers SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
 * 
 * CertPolicyId ::= OBJECT IDENTIFIER
 * 
 * PolicyQualifierInfo ::= SEQUENCE { policyQualifierId PolicyQualifierId,
 * qualifier ANY DEFINED BY policyQualifierId }
 * 
 * PolicyQualifierId ::= OBJECT IDENTIFIER (id-qt-cps | id-qt-unotice)
 * 
 */

public class CertificatePoliciesType {

	private Boolean critical;
	private Map<String, List<PolicyQualifierInfo>> policyInfoMap;

	public CertificatePoliciesType() {
		critical = false;

		policyInfoMap = new HashMap<>();
	}

	public Boolean addPolicyQualifier(String policyId, String policyQualifierId, String qualifier) {

		if (!policyInfoMap.containsKey(policyId)) {
			policyInfoMap.put(policyId, new ArrayList<PolicyQualifierInfo>());
		}

		// if(!policyInfoMap.containsKey(policyId)) {

		PolicyQualifierInfo q = null;

		if (PolicyQualifierId.id_qt_cps.getId().equals(policyQualifierId)) {
			q = new PolicyQualifierInfo(qualifier);
		} else if (PolicyQualifierId.id_qt_unotice.getId().equals(policyQualifierId)) {
			// NoticeReference nr = new NoticeReference("notice", new
			// ASN1EncodableVector()); // TODO implement notice
			UserNotice un = new UserNotice(null, new DisplayText(DisplayText.CONTENT_TYPE_BMPSTRING, qualifier));
			q = new PolicyQualifierInfo(PolicyQualifierId.id_qt_unotice, un);
		} else {
			return false;
		}

		// if(policyInfoMap.containsKey(policyId)) {
		// policyInfoMap.put(policyId, new ArrayList<PolicyQualifierInfo>());
		// }

		policyInfoMap.get(policyId).add(q);

		return true;
	}

	public CertificatePolicies compile() {

		List<PolicyInformation> pl = new ArrayList<>();

		for (String p : policyInfoMap.keySet()) {
			ASN1EncodableVector v = new ASN1EncodableVector();

			for (PolicyQualifierInfo qi : policyInfoMap.get(p)) {
				v.add(qi);
			}

			PolicyInformation pi = new PolicyInformation(new ASN1ObjectIdentifier(p), new DERSequence(v));
			pl.add(pi);
		}

		return new CertificatePolicies(pl.toArray(new PolicyInformation[pl.size()]));
	}

	public Boolean isCritical() {
		return critical;
	}

	public void setCritical(Boolean critical) {
		this.critical = critical;
	}
}
