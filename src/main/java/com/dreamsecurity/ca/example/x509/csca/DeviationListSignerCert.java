package com.dreamsecurity.ca.example.x509.csca;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.ReasonFlags;

import com.dreamsecurity.ca.util.Constants;
import com.dreamsecurity.ca.util.Validity;
import com.dreamsecurity.ca.util.Constants.ValidityType;
import com.dreamsecurity.ca.x509.core.extension.AuthorityInformationAccessType;
import com.dreamsecurity.ca.x509.core.extension.AuthorityKeyIdentifierType;
import com.dreamsecurity.ca.x509.core.extension.BasicConstraintsType;
import com.dreamsecurity.ca.x509.core.extension.CRLDistributionPointsType;
import com.dreamsecurity.ca.x509.core.extension.ExtendedKeyUsageType;
import com.dreamsecurity.ca.x509.core.extension.IssuerAltNameType;
import com.dreamsecurity.ca.x509.core.extension.KeyUsageType;
import com.dreamsecurity.ca.x509.core.extension.PrivateKeyUsagePeriodType;
import com.dreamsecurity.ca.x509.core.extension.SubjectKeyIdentifierType;
import com.dreamsecurity.ca.x509.core.policy.CertificatePolicy;
import com.dreamsecurity.ca.x509.factory.CertificateFactory;

/**
 * Example for how to generate Deviation List certificate
 * @author dream
 *
 */
public class DeviationListSignerCert {
	public static X509Certificate issueCert(String dn, PublicKey pubKey, X509Certificate signerCert, PrivateKey signingKey) {
		
		CertificatePolicy cp = new CertificatePolicy();
		
		cp.setValidity(new Validity(ValidityType.MONTH, 3));
		cp.setSigningAlgorithm(Constants.SigningAlgo.SHA256WITHRSA.getAlgo());

		// basic constraints
		BasicConstraintsType bc = new BasicConstraintsType();
		bc.setCA(false);
		bc.setCritical(true);

		cp.setBasicConstraints(bc);

		// auth key id
		cp.setAuthKeyId(new AuthorityKeyIdentifierType(signerCert.getPublicKey().getEncoded(),
				signerCert.getSubjectDN().getName(), signerCert.getSerialNumber()));

		// sub key id
		cp.setSubjectKeyid(new SubjectKeyIdentifierType(pubKey.getEncoded()));

		// key usage
		KeyUsageType ku = new KeyUsageType();
		ku.setDigitalSignature(true);
		ku.setNonRepudiation(true);

		cp.setKeyUsage(ku);

		// ext key usage
		ExtendedKeyUsageType eku = new ExtendedKeyUsageType();
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
				signerCert.getSubjectX500Principal().toString(),
				new ReasonFlags(ReasonFlags.unused | ReasonFlags.certificateHold));
		dp.addCrlDisPoint("127.0.0.1", CRLDistributionPointsType.iPAddress,
				signerCert.getSubjectX500Principal().toString(),
				new ReasonFlags(ReasonFlags.cessationOfOperation | ReasonFlags.keyCompromise | ReasonFlags.superseded));

		cp.setCrlDistributionPointsType(dp);

		// issuer alt name
		IssuerAltNameType altName = new IssuerAltNameType();
		altName.addAltName("abc1", IssuerAltNameType.dNSName);
		altName.addAltName("http://test.com", IssuerAltNameType.uniformResourceIdentifier);

		cp.setIssuerAltNameType(altName);

		// private key usage
		PrivateKeyUsagePeriodType keyUsagePeriodType = new PrivateKeyUsagePeriodType();
		keyUsagePeriodType.setNotAfter(new Date());
		keyUsagePeriodType.setNotBefore(DateUtils.addMonths(new Date(), 3));

		cp.setPrivateKeyUsagePeriodType(keyUsagePeriodType);

		// mls
		cp.getExtKeyUsageType()
		.addExtKeyUsage(KeyPurposeId.getInstance(ICAOObjectIdentifiers.id_icao_mrtd_security.branch("8"))); 

		// issue certificate
		CertificateFactory fac = new CertificateFactory(cp);

		fac.setCertificatePolicy(cp);

		X509Certificate cert = null;

		cert = fac.issueCertificate(BigInteger.valueOf(new Random().nextInt()),
				signerCert.getSubjectX500Principal().toString(),
				dn, pubKey,
				signingKey);

		return cert;

	}
}
