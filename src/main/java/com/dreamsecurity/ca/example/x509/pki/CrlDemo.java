package com.dreamsecurity.ca.example.x509.pki;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.CRLReason;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.x509.ReasonFlags;

import com.dreamsecurity.ca.x509.core.CrlType;
import com.dreamsecurity.ca.x509.core.extension.AuthorityInformationAccessType;
import com.dreamsecurity.ca.x509.core.extension.AuthorityKeyIdentifierType;
import com.dreamsecurity.ca.x509.core.extension.CRLDistributionPointsType;
import com.dreamsecurity.ca.x509.core.extension.ExpiredCertsOnCRLType;
import com.dreamsecurity.ca.x509.core.extension.FreshestCRLType;
import com.dreamsecurity.ca.x509.core.extension.IssuingDistributionPointType;
import com.dreamsecurity.ca.x509.core.policy.CrlPolicy;
import com.dreamsecurity.ca.x509.factory.CrlFactory;

public class CrlDemo {

	public X509CRL issueCrl(PrivateKey signingKey, X509Certificate signerCert, String signAlgo,
			int crlNo, boolean isDelta) {
		
		X509CRL crl = null;
		
		CrlPolicy crlPolicy = new CrlPolicy();
		
		// auth id
		AuthorityKeyIdentifierType authId = new AuthorityKeyIdentifierType(signerCert.getPublicKey().getEncoded());
		//authId.setAuthCertIssuer(signerCert.getSubjectX500Principal().toString());
		//authId.setAuthCertSerialNumber(signerCert.getSerialNumber());
		crlPolicy.setAuthKeyId(authId);
		
		// crl dp
		IssuingDistributionPointType idp = new IssuingDistributionPointType();
		idp.addIssuingDisPoint("ldap://test.com", CRLDistributionPointsType.dNSName, 
				new ReasonFlags(CRLReason.CESSATION_OF_OPERATION.ordinal()), false, true, false, false);
		crlPolicy.setIssuingDistributionPoint(idp);
		
		// freshest dp
		FreshestCRLType fdp = new FreshestCRLType();
		fdp.addCrlDisPoint("ldap://test.com", FreshestCRLType.dNSName, 
				signerCert.getSubjectX500Principal().toString(), new ReasonFlags(CRLReason.CERTIFICATE_HOLD.ordinal()));
		crlPolicy.setFreshestCRLType(fdp);
		
		// expired cert on crl 
		ExpiredCertsOnCRLType expiredCertsOnCRL = new ExpiredCertsOnCRLType(new Date());		
		crlPolicy.setExpiredCertsOnCRL(expiredCertsOnCRL);
		
		// aia
		AuthorityInformationAccessType aia = new AuthorityInformationAccessType();
		aia.addAIA("test", AuthorityInformationAccessType.id_ad_ocsp);
		crlPolicy.setAia(aia);
		
		// create crl
		CrlFactory crlFactory = new CrlFactory(crlPolicy);
		
		// crl list
		List<CrlType> crlList = new ArrayList<CrlType>();
		crlList.add(new CrlType(BigInteger.valueOf(11), CRLReason.CERTIFICATE_HOLD.ordinal(), new Date()));
		crlList.add(new CrlType(BigInteger.valueOf(22), CRLReason.CESSATION_OF_OPERATION.ordinal(), DateUtils.addDays(new Date(), 3)));
				
		if(!isDelta) {
			crl = crlFactory.issueCrl(signingKey, signerCert, new Date(), DateUtils.addDays(new Date(), 7), 
					signAlgo, crlNo, crlList);
		} else {
			crl = crlFactory.issueDeltaCrl(signingKey, signerCert, new Date(), DateUtils.addDays(new Date(), 7), 
					signAlgo, crlNo, crlNo, crlList );
		}
		
		return crl;
	}
	
}
