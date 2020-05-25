package com.dreamsecurity.ca.example.x509.csca;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.lang3.time.DateUtils;

import com.dreamsecurity.ca.util.Constants;
import com.dreamsecurity.ca.util.Validity;
import com.dreamsecurity.ca.util.Constants.ValidityType;
import com.dreamsecurity.ca.x509.core.extension.AuthorityKeyIdentifierType;
import com.dreamsecurity.ca.x509.core.extension.BasicConstraintsType;
import com.dreamsecurity.ca.x509.core.extension.DNType;
import com.dreamsecurity.ca.x509.core.extension.KeyUsageType;
import com.dreamsecurity.ca.x509.core.extension.NameChangeType;
import com.dreamsecurity.ca.x509.core.extension.PrivateKeyUsagePeriodType;
import com.dreamsecurity.ca.x509.core.extension.SubjectKeyIdentifierType;
import com.dreamsecurity.ca.x509.core.policy.CertificatePolicy;
import com.dreamsecurity.ca.x509.factory.CertificateFactory;

/**
 * Example for how to generate Link certificate
 * @author dream
 *
 */
public class LinkCertificate {

	public static X509Certificate issueLinkCert(KeyPair keyPair, KeyPair newKeyPair) {

		CertificatePolicy cp = new CertificatePolicy();

		cp.setValidity(new Validity(ValidityType.MONTH, 3));
		cp.setSigningAlgorithm(Constants.SigningAlgo.SHA256WITHRSA.getAlgo());
		
		// basic constraints
		BasicConstraintsType bc = new BasicConstraintsType();
		bc.setCA(true);
		bc.setCritical(true);
		// bc.setPathLenConstraint(0);

		cp.setBasicConstraints(bc);

		// auth key id
		cp.setAuthKeyId(new AuthorityKeyIdentifierType(keyPair.getPublic().getEncoded()));

		// sub key id
		cp.setSubjectKeyid(new SubjectKeyIdentifierType(keyPair.getPublic().getEncoded()));

		// key usage
		KeyUsageType ku = new KeyUsageType();
		ku.setCRLSign(true);
		ku.setDigitalSignature(true);
		ku.setKeyCertSign(true);
		cp.setKeyUsage(ku);

		// name change
		NameChangeType nc = new NameChangeType();
		cp.setNameChangeType(nc);

		// private key usage
		PrivateKeyUsagePeriodType keyUsagePeriodType = new PrivateKeyUsagePeriodType();
		keyUsagePeriodType.setNotAfter(new Date());
		keyUsagePeriodType.setNotBefore(DateUtils.addMonths(new Date(), 3));

		cp.setPrivateKeyUsagePeriodType(keyUsagePeriodType);

		CertificateFactory fac = new CertificateFactory(cp);

		DNType dn = new DNType();
		dn.setCommonName("link");
		dn.setOrganizationalUnit("test");
		dn.setOrganization("dream");
		dn.setCountry("KR");

		fac.setCertificatePolicy(cp);

		X509Certificate cert = null;

		cert = fac.issueCertificate(BigInteger.valueOf(2), dn.buildDNString(), 
				dn.buildDNString(), keyPair.getPublic(),
				keyPair.getPrivate());

		return cert;
	}

}
