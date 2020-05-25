package com.dreamsecurity.ca.example.x509.pki;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.dreamsecurity.ca.util.Validity;
import com.dreamsecurity.ca.util.Constants.SigningAlgo;
import com.dreamsecurity.ca.util.Constants.ValidityType;
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
import com.dreamsecurity.ca.x509.core.extension.SubjectKeyIdentifierType;
import com.dreamsecurity.ca.x509.core.policy.CertificatePolicy;
import com.dreamsecurity.ca.x509.factory.CertificateFactory;

public class CertDemo {
	
	public static X509Certificate issueCert(String dnStr, X509Certificate rootCA, PublicKey subjectPubKey,
			String signAlgo, Date validFrom, Date validTo, PrivateKey signingKey) {
		
		CertificatePolicy cp = createCertPolicy(rootCA, subjectPubKey);
			
		// issue certificate
		CertificateFactory fac = new CertificateFactory(cp);

		fac.setCertificatePolicy(cp);

		X509Certificate cert = null;

		cert = fac.issueCertificate(BigInteger.valueOf(new Random().nextInt()), rootCA.getSubjectX500Principal().toString(),
				dnStr, subjectPubKey, signingKey);

		return cert;

	}

	public static X509Certificate issueCert(X509Certificate rootCA, PKCS10CertificationRequest request,
			String signAlgo, Date validFrom, Date validTo, PrivateKey signingKey) {
		
		JcaPEMKeyConverter c = new JcaPEMKeyConverter();
		PublicKey subjectPubKey = null;
		try {
			subjectPubKey = c.getPublicKey(request.getSubjectPublicKeyInfo());
		} catch (PEMException e) {
			
			e.printStackTrace();
		}
		
		CertificatePolicy cp = createCertPolicy(rootCA, subjectPubKey);
		
		// issue certificate
		CertificateFactory fac = new CertificateFactory(cp);

		fac.setCertificatePolicy(cp);

		X509Certificate cert = null;

		try {
			cert = fac.issueCertificate(BigInteger.valueOf(new Random().nextInt()), rootCA.getSubjectX500Principal().toString(),
					signingKey, request.getEncoded() );
		} catch (IOException e) {
			
			e.printStackTrace();
		}

		return cert;
		
	}
	
	public static X509Certificate issueCA(String dnStr, BigInteger serialNo, KeyPair keyPair, String signAlgo,
			Date validFrom, Date validTo) {
		
		CertificatePolicy cp = new CertificatePolicy();

		// basic constraints
		BasicConstraintsType bc = new BasicConstraintsType();
		bc.setCA(true);
		bc.setCritical(true);
		//bc.setPathLenConstraint(0);

		cp.setBasicConstraints(bc);

		// auth key id
		cp.setAuthKeyId(new AuthorityKeyIdentifierType(keyPair.getPublic().getEncoded()));

		// sub key id
		cp.setSubjectKeyid(new SubjectKeyIdentifierType(keyPair.getPublic().getEncoded()));

		// key usage
		KeyUsageType ku = new KeyUsageType();
		ku.setCritical(false);
		ku.setCRLSign(true);
		ku.setDigitalSignature(true);
		ku.setKeyCertSign(true);
		cp.setKeyUsage(ku);

		// ext key usage
		ExtendedKeyUsageType eku = new ExtendedKeyUsageType();
		eku.setCritical(false);
		eku.addExtKeyUsage(KeyPurposeId.id_kp_serverAuth); // just for test
		cp.setExtKeyUsage(eku);
		
		cp.setValidity(new Validity(ValidityType.YEAR, 3));
		cp.setSigningAlgorithm(signAlgo);

		CertificateFactory fac = new CertificateFactory(cp);

		fac.setCertificatePolicy(cp);

		X509Certificate cert = null;

		cert = fac.issueCertificate(serialNo, dnStr, dnStr, keyPair.getPublic(),
				keyPair.getPrivate());

		return cert;

	}
		
	private static CertificatePolicy createCertPolicy(X509Certificate rootCA, PublicKey subjectPubKey) {
		CertificatePolicy cp = new CertificatePolicy();

		// validity
		cp.setValidity(new Validity(ValidityType.MONTH, 3));
		
		// signing algo
		cp.setSigningAlgorithm(SigningAlgo.SHA256WITHRSA.getAlgo());		
		
		// basic constraints
		BasicConstraintsType bc = new BasicConstraintsType();
		bc.setCA(false);
		bc.setCritical(true);

		cp.setBasicConstraints(bc);

		// auth key id
		cp.setAuthKeyId(new AuthorityKeyIdentifierType(rootCA.getPublicKey().getEncoded(),
				rootCA.getSubjectDN().getName(), rootCA.getSerialNumber()));

		// sub key id
		cp.setSubjectKeyid(new SubjectKeyIdentifierType(subjectPubKey.getEncoded()));

		// key usage
		KeyUsageType ku = new KeyUsageType();
		ku.setCritical(false);
		ku.setDataEncipherment(true);
		ku.setDigitalSignature(true);
		ku.setKeyAgreement(true);
		ku.setKeyEncipherment(true);
		ku.setNonRepudiation(true);

		cp.setKeyUsage(ku);

		// ext key usage
		ExtendedKeyUsageType eku = new ExtendedKeyUsageType();
		eku.setCritical(false);
		eku.addExtKeyUsage(KeyPurposeId.id_kp_serverAuth);
		eku.addExtKeyUsage(KeyPurposeId.id_kp_clientAuth);
		eku.addExtKeyUsage(KeyPurposeId.id_kp_codeSigning);
		eku.addExtKeyUsage(KeyPurposeId.id_kp_OCSPSigning);
		eku.addExtKeyUsage(KeyPurposeId.id_kp_timeStamping);
		
		cp.setExtKeyUsage(eku);

		// auth info access
		AuthorityInformationAccessType accessType = new AuthorityInformationAccessType();
		accessType.addAIA("http://ocsp.test.com", AuthorityInformationAccessType.id_ad_ocsp);
		accessType.addAIA("http://ca.test.com", AuthorityInformationAccessType.id_ad_caIssuers);
		accessType.addAIA("http://repo.test.com", AuthorityInformationAccessType.id_ad_caRepository);

		cp.setAuthorityInformationAccessType(accessType);
		// crl dp
		CRLDistributionPointsType dp = new CRLDistributionPointsType();

		dp.addCrlDisPoint("ldap://crldp.test.dp1", CRLDistributionPointsType.dNSName,
				rootCA.getSubjectX500Principal().toString(),
				new ReasonFlags(ReasonFlags.unused | ReasonFlags.certificateHold));
		dp.addCrlDisPoint("127.0.0.1", CRLDistributionPointsType.iPAddress, rootCA.getSubjectX500Principal().toString(),
				new ReasonFlags(ReasonFlags.cessationOfOperation | ReasonFlags.keyCompromise | ReasonFlags.superseded));

		cp.setCrlDistributionPointsType(dp);

		// cert policy
		CertificatePoliciesType certPol = new CertificatePoliciesType();		
		certPol.addPolicyQualifier("1.2.3.4.5", PolicyQualifierId.id_qt_cps.getId(), "this is a test qualifier");
		certPol.addPolicyQualifier("1.2.3.4.5", PolicyQualifierId.id_qt_cps.getId(), "this is a test qualifier");
		certPol.addPolicyQualifier("1.2.3.4.6", PolicyQualifierId.id_qt_unotice.getId(), "this is a test qualifier");
		certPol.addPolicyQualifier("1.2.3.4.6", PolicyQualifierId.id_qt_unotice.getId(), "this is a test qualifier");
		
		cp.setCertPolicy(certPol);
		
		// Inhibit any policy
		InhibitAnyPolicyType inhibitAnyPolicy = new InhibitAnyPolicyType();
		inhibitAnyPolicy.setValue(BigInteger.valueOf(10));

		cp.setAnyPolicyType(inhibitAnyPolicy);

		// issuer alt name
		IssuerAltNameType altName = new IssuerAltNameType();
		altName.addAltName("abc1", IssuerAltNameType.dNSName);
		altName.addAltName("http://test.com", IssuerAltNameType.uniformResourceIdentifier);

		cp.setIssuerAltNameType(altName);

		// name constraints
		NameConstraintsType nameConstraintsType = new NameConstraintsType();
		nameConstraintsType.addPermittedName(NameConstraintsType.rfc822Name, "rfc822name");
		nameConstraintsType.addExcluededName(NameConstraintsType.dNSName, "dNSName");

		cp.setNameConstraintsType(nameConstraintsType);

		// policy constraint
		PolicyConstraintsType policyConstraintsType = new PolicyConstraintsType();
		policyConstraintsType.addInhibitPolicyMapping(BigInteger.valueOf(111));
		policyConstraintsType.addRequireExplicitPolicy(BigInteger.valueOf(222));

		cp.setPolicyConstraintsType(policyConstraintsType);

		// policy mapping type
		PolicyMappingType mappingType = new PolicyMappingType();
		mappingType.addPolicyMapping("1.2.3.4.5", "2.1.2.1.2");
		mappingType.addPolicyMapping("1.1.1.1.5", "2.2.1.1.4");

		cp.setPolicyMappingType(mappingType);
		
		// private key usage
		PrivateKeyUsagePeriodType keyUsagePeriodType = new PrivateKeyUsagePeriodType();
		keyUsagePeriodType.setNotAfter(new Date());
		keyUsagePeriodType.setNotBefore(DateUtils.addMonths(new Date(), 3));
		
		cp.setPrivateKeyUsagePeriodType(keyUsagePeriodType);
		
		// subject alt name
		SubjectAltNameType subAltNameType = new SubjectAltNameType();
		subAltNameType.addAltName("subject alt name", SubjectAltNameType.rfc822Name);
		
		cp.setSubjectAltNameType(subAltNameType);
		
		// subject directory attr
		SubjectDirectoryAttributesType directoryAttributesType = new SubjectDirectoryAttributesType();
		directoryAttributesType.addAttribute("01012313134", SubjectDirectoryAttributesType.mobileTelephoneNumberOidStr);
		
		cp.setSubjectDirectoryAttributesType(directoryAttributesType);
		
		// subject info access
		SubjectInformationAccessType subInfoAccessType = new SubjectInformationAccessType();
		subInfoAccessType.addAIA("test", SubjectInformationAccessType.id_ad_ocsp);
		
		cp.setSubjectInformationAccessType(subInfoAccessType);
		
		// Freshest CRL
		FreshestCRLType freshestCRLType = new FreshestCRLType();
		freshestCRLType.addCrlDisPoint("ldap://deltacrl.test.dp1", CRLDistributionPointsType.dNSName,
				rootCA.getSubjectX500Principal().toString(),
				new ReasonFlags(ReasonFlags.unused | ReasonFlags.certificateHold));				
		
		cp.setFreshestCRLType(freshestCRLType);
		
		////////////// ICAO-PKI CSCA /////////
		// DS - doc type
		DocumentTypeList docTypeList = new DocumentTypeList();
		docTypeList.init(new String[] { "ID", "P" });

		cp.setDocTypeList(docTypeList);

		// LINK Cert - name change
		NameChangeType nct = new NameChangeType();
		cp.setNameChangeType(nct);
		
		// mls
		cp.getExtKeyUsageType().addExtKeyUsage(KeyPurposeId.getInstance
				(ICAOObjectIdentifiers.id_icao_cscaMasterListSigningKey));
				
		// dls
		cp.getExtKeyUsageType().addExtKeyUsage(KeyPurposeId.getInstance
				(ICAOObjectIdentifiers.id_icao_mrtd_security.branch("8"))); // deviation list signer
		
		//////////////////////////////
		
		return cp;
	}
}
