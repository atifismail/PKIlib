package com.dreamsecurity.ca.x509.core.policy;

import com.dreamsecurity.ca.x509.core.extension.AuthorityInformationAccessType;
import com.dreamsecurity.ca.x509.core.extension.AuthorityKeyIdentifierType;
import com.dreamsecurity.ca.x509.core.extension.ExpiredCertsOnCRLType;
import com.dreamsecurity.ca.x509.core.extension.FreshestCRLType;
import com.dreamsecurity.ca.x509.core.extension.IssuingDistributionPointType;

/**
 * Defines CRL properties/extensions
 * @author dream
 *
 */
public class CrlPolicy {

	private AuthorityKeyIdentifierType authKeyId;
	private IssuingDistributionPointType issuingDistributionPointsType;
	private FreshestCRLType freshestCRLType;
	private ExpiredCertsOnCRLType expiredCertsOnCRL;
	private AuthorityInformationAccessType aia;
		
	public AuthorityKeyIdentifierType getAuthKeyId() {
		return authKeyId;
	}
	public void setAuthKeyId(AuthorityKeyIdentifierType authKeyId) {
		this.authKeyId = authKeyId;
	}
	public IssuingDistributionPointType getIssuingDistributionPoint() {
		return this.issuingDistributionPointsType;
	}
	public void setIssuingDistributionPoint(IssuingDistributionPointType issuingDistributionPointsType) {
		this.issuingDistributionPointsType = issuingDistributionPointsType;
	}
	public FreshestCRLType getFreshestCRLType() {
		return freshestCRLType;
	}
	public void setFreshestCRLType(FreshestCRLType freshestCRLType) {
		this.freshestCRLType = freshestCRLType;
	}
	public ExpiredCertsOnCRLType getExpiredCertsOnCRL() {
		return expiredCertsOnCRL;
	}
	public void setExpiredCertsOnCRL(ExpiredCertsOnCRLType expiredCertsOnCRL) {
		this.expiredCertsOnCRL = expiredCertsOnCRL;
	}
	public AuthorityInformationAccessType getAia() {
		return aia;
	}
	public void setAia(AuthorityInformationAccessType aia2) {
		this.aia = aia2;
	}
	
	
}
