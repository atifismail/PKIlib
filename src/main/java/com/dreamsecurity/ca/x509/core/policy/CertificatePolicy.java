package com.dreamsecurity.ca.x509.core.policy;

import com.dreamsecurity.ca.util.Validity;
import com.dreamsecurity.ca.x509.core.extension.AuthorityInformationAccessType;
import com.dreamsecurity.ca.x509.core.extension.AuthorityKeyIdentifierType;
import com.dreamsecurity.ca.x509.core.extension.BasicConstraintsType;
import com.dreamsecurity.ca.x509.core.extension.CRLDistributionPointsType;
import com.dreamsecurity.ca.x509.core.extension.CertificatePoliciesType;
import com.dreamsecurity.ca.x509.core.extension.DocumentTypeList;
import com.dreamsecurity.ca.x509.core.extension.ExtendedKeyUsageType;
import com.dreamsecurity.ca.x509.core.extension.FreshestCRLType;
import com.dreamsecurity.ca.x509.core.extension.InhibitAnyPolicyType;
import com.dreamsecurity.ca.x509.core.extension.IssuerAltNameType;
import com.dreamsecurity.ca.x509.core.extension.KeyUsageType;
import com.dreamsecurity.ca.x509.core.extension.NameChangeType;
import com.dreamsecurity.ca.x509.core.extension.NameConstraintsType;
import com.dreamsecurity.ca.x509.core.extension.PolicyConstraintsType;
import com.dreamsecurity.ca.x509.core.extension.PolicyMappingType;
import com.dreamsecurity.ca.x509.core.extension.PrivateKeyUsagePeriodType;
import com.dreamsecurity.ca.x509.core.extension.SubjectAltNameType;
import com.dreamsecurity.ca.x509.core.extension.SubjectDirectoryAttributesType;
import com.dreamsecurity.ca.x509.core.extension.SubjectInformationAccessType;
import com.dreamsecurity.ca.x509.core.extension.SubjectKeyIdentifierType;;

/**
 * Defines certificate properties including extention, validity, signing algorithm etc
 * @author dream
 *
 */
public class CertificatePolicy {

	private Validity validity;
	private String signingAlgorithm;
	
	
	private BasicConstraintsType basicConstraints;
	private KeyUsageType keyUsageType;
	private ExtendedKeyUsageType extKeyUsageType;
	private AuthorityKeyIdentifierType authKeyId;
	private SubjectKeyIdentifierType subjectKeyId;
	private CertificatePoliciesType certPolicy;
	private DocumentTypeList docTypeList;
	private FreshestCRLType freshestCRLType;
	private InhibitAnyPolicyType anyPolicyType;
	private CRLDistributionPointsType crlDistributionPointsType;
	private IssuerAltNameType issuerAltNameType;
	private NameChangeType nameChangeType;
	private NameConstraintsType nameConstraintsType;
	private PolicyConstraintsType policyConstraintsType;
	private PolicyMappingType policyMappingType;
	private PrivateKeyUsagePeriodType privateKeyUsagePeriodType;
	private SubjectAltNameType subjectAltNameType;
	private SubjectDirectoryAttributesType subjectDirectoryAttributesType;
	private SubjectInformationAccessType subjectInformationAccessType;
	private SubjectKeyIdentifierType subjectKeyIdentifierType;
	private AuthorityInformationAccessType authorityInformationAccessType;
	
	public CertificatePolicy() {
		basicConstraints = null;
		keyUsageType = null;
		extKeyUsageType = null;
		authKeyId = null;
		subjectKeyId = null;
		certPolicy = null;
		docTypeList = null;
		freshestCRLType = null;
		anyPolicyType = null;
		crlDistributionPointsType = null;
		issuerAltNameType = null;
		nameChangeType = null;
		nameConstraintsType = null;
		policyConstraintsType = null;
		policyMappingType = null;
		privateKeyUsagePeriodType = null;
		subjectAltNameType = null;
		subjectDirectoryAttributesType = null;
		subjectInformationAccessType = null;
		subjectKeyIdentifierType = null;
		authorityInformationAccessType = null;
	}
	
	public DocumentTypeList getDocTypeList() {
		return this.docTypeList;
	}
	
	public void setDocTypeList(DocumentTypeList dtl) {
		this.docTypeList = dtl;
	}
	
	public void setBasicConstraints(BasicConstraintsType arg) {
		this.basicConstraints = arg;
	}
	
	public void setKeyUsage(KeyUsageType arg) {
		this.keyUsageType = arg;
	} 
	
	public void setAuthKeyId(AuthorityKeyIdentifierType arg) {
		this.authKeyId = arg;
	}
	
	public void setSubjectKeyid(SubjectKeyIdentifierType arg) {
		this.subjectKeyId = arg;
	}
	
	public void setExtKeyUsage(ExtendedKeyUsageType extKeyUsageType) {
		this.extKeyUsageType = extKeyUsageType;
	}

	public BasicConstraintsType getBasicConstraints() {
		return basicConstraints;
	}

	public KeyUsageType getKeyUsageType() {
		return keyUsageType;
	}

	public ExtendedKeyUsageType getExtKeyUsageType() {
		return extKeyUsageType;
	}

	public AuthorityKeyIdentifierType getAuthKeyId() {
		return authKeyId;
	}

	public SubjectKeyIdentifierType getSubjectKeyId() {
		return subjectKeyId;
	}

	public CertificatePoliciesType getCertPolicy() {
		return certPolicy;
	}

	public void setCertPolicy(CertificatePoliciesType certPolicy) {
		this.certPolicy = certPolicy;
	}

	public FreshestCRLType getFreshestCRLType() {
		return freshestCRLType;
	}

	public void setFreshestCRLType(FreshestCRLType freshestCRLType) {
		this.freshestCRLType = freshestCRLType;
	}

	public InhibitAnyPolicyType getAnyPolicyType() {
		return anyPolicyType;
	}

	public void setAnyPolicyType(InhibitAnyPolicyType anyPolicyType) {
		this.anyPolicyType = anyPolicyType;
	}

	public CRLDistributionPointsType getCrlDistributionPointsType() {
		return crlDistributionPointsType;
	}

	public void setCrlDistributionPointsType(CRLDistributionPointsType crlDistributionPointsType) {
		this.crlDistributionPointsType = crlDistributionPointsType;
	}

	public IssuerAltNameType getIssuerAltNameType() {
		return issuerAltNameType;
	}

	public void setIssuerAltNameType(IssuerAltNameType issuerAlgNameType) {
		this.issuerAltNameType = issuerAlgNameType;
	}

	public NameChangeType getNameChangeType() {
		return nameChangeType;
	}

	public void setNameChangeType(NameChangeType nameChangeType) {
		this.nameChangeType = nameChangeType;
	}

	public NameConstraintsType getNameConstraintsType() {
		return nameConstraintsType;
	}

	public void setNameConstraintsType(NameConstraintsType nameConstraintsType) {
		this.nameConstraintsType = nameConstraintsType;
	}

	public PolicyConstraintsType getPolicyConstraintsType() {
		return policyConstraintsType;
	}

	public void setPolicyConstraintsType(PolicyConstraintsType policyConstraintsType) {
		this.policyConstraintsType = policyConstraintsType;
	}

	public PolicyMappingType getPolicyMappingType() {
		return policyMappingType;
	}

	public void setPolicyMappingType(PolicyMappingType policyMappingType) {
		this.policyMappingType = policyMappingType;
	}

	public PrivateKeyUsagePeriodType getPrivateKeyUsagePeriodType() {
		return privateKeyUsagePeriodType;
	}

	public void setPrivateKeyUsagePeriodType(PrivateKeyUsagePeriodType privateKeyUsagePeriodType) {
		this.privateKeyUsagePeriodType = privateKeyUsagePeriodType;
	}

	public SubjectAltNameType getSubjectAltNameType() {
		return subjectAltNameType;
	}

	public void setSubjectAltNameType(SubjectAltNameType subjectAltNameType) {
		this.subjectAltNameType = subjectAltNameType;
	}

	public SubjectDirectoryAttributesType getSubjectDirectoryAttributesType() {
		return subjectDirectoryAttributesType;
	}

	public void setSubjectDirectoryAttributesType(SubjectDirectoryAttributesType subjectDirectoryAttributesType) {
		this.subjectDirectoryAttributesType = subjectDirectoryAttributesType;
	}

	public SubjectInformationAccessType getSubjectInformationAccessType() {
		return subjectInformationAccessType;
	}

	public void setSubjectInformationAccessType(SubjectInformationAccessType subjectInformationAccessType) {
		this.subjectInformationAccessType = subjectInformationAccessType;
	}

	public SubjectKeyIdentifierType getSubjectKeyIdentifierType() {
		return subjectKeyIdentifierType;
	}

	public void setSubjectKeyIdentifierType(SubjectKeyIdentifierType subjectKeyIdentifierType) {
		this.subjectKeyIdentifierType = subjectKeyIdentifierType;
	}

	public AuthorityInformationAccessType getAuthorityInformationAccessType() {
		return authorityInformationAccessType;
	}

	public void setAuthorityInformationAccessType(AuthorityInformationAccessType authorityInformationAccessType) {
		this.authorityInformationAccessType = authorityInformationAccessType;
	}

	public String getSigningAlgorithm() {
		return signingAlgorithm;
	}

	public void setSigningAlgorithm(String signingAlgorithm) {
		this.signingAlgorithm = signingAlgorithm;
	}

	public Validity getValidity() {
		return validity;
	}

	public void setValidity(Validity validity) {
		this.validity = validity;
	}	
}
