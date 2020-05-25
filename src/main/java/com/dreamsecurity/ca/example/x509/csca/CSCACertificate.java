package com.dreamsecurity.ca.example.x509.csca;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.lang3.time.DateUtils;

import com.dreamsecurity.ca.util.Constants;
import com.dreamsecurity.ca.util.Validity;
import com.dreamsecurity.ca.util.Constants.ValidityType;
import com.dreamsecurity.ca.x509.core.extension.AuthorityKeyIdentifierType;
import com.dreamsecurity.ca.x509.core.extension.BasicConstraintsType;
import com.dreamsecurity.ca.x509.core.extension.KeyUsageType;
import com.dreamsecurity.ca.x509.core.extension.PrivateKeyUsagePeriodType;
import com.dreamsecurity.ca.x509.core.extension.SubjectKeyIdentifierType;
import com.dreamsecurity.ca.x509.core.policy.CertificatePolicy;
import com.dreamsecurity.ca.x509.factory.CertificateFactory;

/**
 * Example for how to generate self sign CSCA certificate
 * @author dream
 *
 */
public class CSCACertificate {

	public static X509Certificate issueCSCACert(PublicKey pubKey, PrivateKey priKey, String dn, 
			BigInteger serialNo ) {

		CertificatePolicy cp = new CertificatePolicy();

		cp.setValidity(new Validity(ValidityType.YEAR, 3));
		if(pubKey.getAlgorithm().equals(Constants.KeyAlgo.RSA.toString())) {
			cp.setSigningAlgorithm(Constants.SigningAlgo.SHA256WITHRSA.getAlgo());
		} else if(pubKey.getAlgorithm().equals(Constants.KeyAlgo.EC.toString())) {
			cp.setSigningAlgorithm(Constants.SigningAlgo.SHA256WITHECDSA.getAlgo());
		} else {
			cp.setSigningAlgorithm(Constants.SigningAlgo.SHA256WITHRSA.getAlgo());
		}
				
		// basic constraints
		BasicConstraintsType bc = new BasicConstraintsType();
		bc.setCA(true);
		bc.setCritical(true);
		// bc.setPathLenConstraint(0);

		cp.setBasicConstraints(bc);

		// auth key id
		cp.setAuthKeyId(new AuthorityKeyIdentifierType(pubKey.getEncoded()));

		// sub key id
		cp.setSubjectKeyid(new SubjectKeyIdentifierType(pubKey.getEncoded()));

		// key usage
		KeyUsageType ku = new KeyUsageType();
		ku.setCRLSign(true);
		ku.setDigitalSignature(true);
		ku.setKeyCertSign(true);
		cp.setKeyUsage(ku);

		// private key usage
		PrivateKeyUsagePeriodType keyUsagePeriodType = new PrivateKeyUsagePeriodType();
		keyUsagePeriodType.setNotAfter(new Date());
		keyUsagePeriodType.setNotBefore(DateUtils.addYears(new Date(), 1));

		cp.setPrivateKeyUsagePeriodType(keyUsagePeriodType);

		CertificateFactory fac = new CertificateFactory(cp);

		/*DNType dn = new DNType();
		dn.setCommonName("csca");
		dn.setOrganizationalUnit("test");
		dn.setOrganization("dream");
		dn.setCountry("KR");*/

		fac.setCertificatePolicy(cp);

		X509Certificate cert = null;

		cert = fac.issueCertificate(BigInteger.valueOf(1), dn, dn, pubKey, priKey);

		return cert;
	}

}
