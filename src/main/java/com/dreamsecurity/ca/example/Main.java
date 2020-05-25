package com.dreamsecurity.ca.example;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.eac.CVCertificate;
import org.bouncycastle.asn1.eac.CVCertificateRequest;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.ejbca.cvc.CVCAuthenticatedRequest;

import com.dreamsecurity.ca.example.cvc.bc.CvcDemo;
import com.dreamsecurity.ca.example.x509.csca.CSCACertificate;
import com.dreamsecurity.ca.example.x509.csca.DSCertificate;
import com.dreamsecurity.ca.example.x509.csca.DeviationListSignerCert;
import com.dreamsecurity.ca.example.x509.csca.LinkCertificate;
import com.dreamsecurity.ca.example.x509.csca.MasterList;
import com.dreamsecurity.ca.example.x509.csca.MasterListSignerCert;
import com.dreamsecurity.ca.example.x509.pki.CertDemo;
import com.dreamsecurity.ca.example.x509.pki.CrlDemo;
import com.dreamsecurity.ca.util.Constants;
import com.dreamsecurity.ca.util.CryptoUtil;
import com.dreamsecurity.ca.util.FileUtils;
import com.dreamsecurity.ca.util.KeyGenerator;
import com.dreamsecurity.ca.x509.factory.CertificateRequestFactory;

/**
 * Main demo class for CSCA/CVCA certificates generation
 * 
 * @author dream
 *
 */
public class Main {

	public static void main(String args[])
			throws CertificateEncodingException, IOException, CRLException, OperatorCreationException, CMSException {

		CryptoUtil.installBCProvider();

		// X.509
		PKIDemo();

		// CSCA
		CSCADemo();

		// bouncycastle cvc library
		BC_CVCADemo();

		// ejbca cvc library
		EJBCA_CVCADemo();
	}

	private static void EJBCA_CVCADemo() {
		// max length 16
		final String CA_COUNTRY_CODE = "KR";
		final String CA_HOLDER_MNEMONIC = "CVCA-DEMO";
		final String CA_SEQUENCE_NO = "00001";

		final String OTHER_CA_COUNTRY_CODE = "US";
		final String OTHER_CA_HOLDER_MNEMONIC = "CVCA-OTHR";
		final String OTHER_CA_SEQUENCE_NO = "00001";

		final String DV_COUNTRY_CODE = "KR";
		final String DV_HOLDER_MNEMONIC = "DVCA-DEMO";
		final String DV_SEQUENCE_NO = "00001";

		final String IS_COUNTRY_CODE = "KR";
		final String IS_HOLDER_MNEMONIC = "KRIS-DEMO";
		final String IS_SEQUENCE_NO = "KR001";

		try {

			org.ejbca.cvc.CVCertificate cert = null;

			// issue cvca cert
			cert = com.dreamsecurity.ca.example.cvc.ejbca.CvcDemo.issueCVCA(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC,
					CA_SEQUENCE_NO);

			FileUtils.saveFile("output/cvca/ejbca/CVCACert.ber", cert.getDEREncoded());

			// issue link cert
			cert = com.dreamsecurity.ca.example.cvc.ejbca.CvcDemo.issueCVCALink(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC,
					CA_SEQUENCE_NO);

			FileUtils.saveFile("output/cvca/ejbca/LinkCVCACert.ber", cert.getDEREncoded());
			// issue dv cert
			cert = com.dreamsecurity.ca.example.cvc.ejbca.CvcDemo.issueDVCert(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC,
					CA_SEQUENCE_NO, DV_COUNTRY_CODE, DV_HOLDER_MNEMONIC, DV_SEQUENCE_NO);

			FileUtils.saveFile("output/cvca/ejbca/DVCert.ber", cert.getDEREncoded());
			// issue IS cert
			cert = com.dreamsecurity.ca.example.cvc.ejbca.CvcDemo.issueISCert(DV_COUNTRY_CODE, DV_HOLDER_MNEMONIC,
					DV_SEQUENCE_NO, IS_COUNTRY_CODE, IS_HOLDER_MNEMONIC, IS_SEQUENCE_NO);

			FileUtils.saveFile("output/cvca/ejbca/ISCert.ber", cert.getDEREncoded());

			// issue cert request
			KeyPair authkp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());

			CVCAuthenticatedRequest req = com.dreamsecurity.ca.example.cvc.ejbca.CvcDemo.issueDVRequest(DV_COUNTRY_CODE,
					DV_HOLDER_MNEMONIC, DV_SEQUENCE_NO, OTHER_CA_COUNTRY_CODE, OTHER_CA_HOLDER_MNEMONIC,
					OTHER_CA_SEQUENCE_NO, authkp);
			FileUtils.saveFile("output/cvca/ejbca/DVCertReq.ber", req.getDEREncoded());

			// verify inner sig
			if (com.dreamsecurity.ca.example.cvc.ejbca.CvcDemo.verifyInnerSign(req.getDEREncoded())) {
				System.out.println("Valid inner signature");
			} else {
				System.err.println("Invalid inner signature");
			}

			// verify outer sig
			if (com.dreamsecurity.ca.example.cvc.ejbca.CvcDemo.verifyOuterSign(req.getDEREncoded(),
					authkp.getPublic())) {
				System.out.println("Valid outer signature");
			} else {
				System.err.println("Invalid outer signature");
			}

		} catch (IOException e) {

			e.printStackTrace();
		}

	}

	private static void BC_CVCADemo() {
		// max length 16
		final String CA_COUNTRY_CODE = "KR";
		final String CA_HOLDER_MNEMONIC = "CVCA-DEMO";
		final String CA_SEQUENCE_NO = "00001";

		final String OTHER_CA_COUNTRY_CODE = "US";
		final String OTHER_CA_HOLDER_MNEMONIC = "CVCA-OTHR";
		final String OTHER_CA_SEQUENCE_NO = "00001";

		final String DV_COUNTRY_CODE = "KR";
		final String DV_HOLDER_MNEMONIC = "DVCA-DEMO";
		final String DV_SEQUENCE_NO = "00001";

		final String IS_COUNTRY_CODE = "KR";
		final String IS_HOLDER_MNEMONIC = "KRIS-DEMO";
		final String IS_SEQUENCE_NO = "KR001";

		try {

			CVCertificate cert = null;

			// issue cvca cert
			cert = CvcDemo.issueCVCA(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);

			FileUtils.saveFile("output/cvca/bc/CVCACert.ber", cert.getEncoded(ASN1Encoding.DER));

			// issue link cert
			cert = CvcDemo.issueCVCALink(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);

			FileUtils.saveFile("output/cvca/bc/LinkCVCACert.ber", cert.getEncoded(ASN1Encoding.DER));
			// issue dv cert
			cert = CvcDemo.issueDVCert(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO, DV_COUNTRY_CODE,
					DV_HOLDER_MNEMONIC, DV_SEQUENCE_NO);

			FileUtils.saveFile("output/cvca/bc/DVCert.ber", cert.getEncoded(ASN1Encoding.DER));
			// issue IS cert
			cert = CvcDemo.issueISCert(DV_COUNTRY_CODE, DV_HOLDER_MNEMONIC, DV_SEQUENCE_NO, IS_COUNTRY_CODE,
					IS_HOLDER_MNEMONIC, IS_SEQUENCE_NO);

			FileUtils.saveFile("output/cvca/bc/ISCert.ber", cert.getEncoded(ASN1Encoding.DER));

			// issue cert request
			CVCertificateRequest req = CvcDemo.issueDVRequest(DV_COUNTRY_CODE, DV_HOLDER_MNEMONIC, DV_SEQUENCE_NO,
					OTHER_CA_COUNTRY_CODE, OTHER_CA_HOLDER_MNEMONIC, OTHER_CA_SEQUENCE_NO);
			FileUtils.saveFile("output/cvca/bc/DVCertReq.ber", req.getEncoded(ASN1Encoding.DER));

			// verify inner sig
			if (CvcDemo.verifyInnerSign(req.getEncoded(ASN1Encoding.DER))) {
				System.out.println("Valid inner signature");
			} else {
				System.err.println("Invalid inner signature");
			}

			// verify outer sig

			if (CvcDemo.verifyOuterSign(req.getEncoded(ASN1Encoding.DER), req.getPublicKey())) {
				System.out.println("Valid outer signature");
			} else {
				System.err.println("Invalid outer signature");
			}

		} catch (IOException e) {

			e.printStackTrace();
		}
	}

	private static void CSCADemo()
			throws CertificateEncodingException, IOException, OperatorCreationException, CMSException {

		/////////////// CSCA //////////////////
		KeyPair cakeyPair = KeyGenerator.getInstance().generateRSAPair(Constants.RSAKeyLength.RSA_2048.getValue());

		// csca cert
		X509Certificate csca = CSCACertificate.issueCSCACert(cakeyPair.getPublic(), cakeyPair.getPrivate(),
				"cn=csca,ou=demo,o=drem,c=KR", BigInteger.valueOf(1));
		FileUtils.saveFile("output/csca/csca.der", csca.getEncoded());

		// link cert
		KeyPair newKeyPair = KeyGenerator.getInstance().generateRSAPair(Constants.RSAKeyLength.RSA_2048.getValue());
		X509Certificate linkCert = LinkCertificate.issueLinkCert(cakeyPair, newKeyPair);
		FileUtils.saveFile("output/csca/linkCert.der", linkCert.getEncoded());

		// ds cert
		KeyPair dsCertKeyPair = KeyGenerator.getInstance().generateRSAPair(Constants.RSAKeyLength.RSA_2048.getValue());
		X509Certificate dsCert = DSCertificate.issueCert("cn=ds,ou=demo,o=dream,c=KR", dsCertKeyPair.getPublic(), csca,
				cakeyPair.getPrivate());
		FileUtils.saveFile("output/csca/ds.der", dsCert.getEncoded());

		// dls cert
		KeyPair dlCertKeyPair = KeyGenerator.getInstance().generateRSAPair(Constants.RSAKeyLength.RSA_2048.getValue());
		X509Certificate dlsCert = DeviationListSignerCert.issueCert("cn=dls,ou=demo,o=dream,c=KR",
				dlCertKeyPair.getPublic(), csca, cakeyPair.getPrivate());
		FileUtils.saveFile("output/csca/dls.der", dlsCert.getEncoded());

		// mls cert
		KeyPair mlCertKeyPair = KeyGenerator.getInstance().generateRSAPair(Constants.RSAKeyLength.RSA_2048.getValue());
		X509Certificate mlsCert = MasterListSignerCert.issueCert("cn=mls,ou=demo,o=dream,c=KR",
				mlCertKeyPair.getPublic(), csca, cakeyPair.getPrivate());
		FileUtils.saveFile("output/csca/mls.der", mlsCert.getEncoded());

		// ml
		byte[] ml = MasterList.createMasterListCMS(mlsCert, mlCertKeyPair.getPrivate(), csca,
				new X509Certificate[] { csca, csca });
		FileUtils.saveFile("output/csca/ml_cms.ber", ml);
		
		// get ml content
		@SuppressWarnings("unused")
		List<X509Certificate> mlCertList = CryptoUtil.getMasterListCertsList(ml);

		// verify ml
		boolean result = CryptoUtil.verifyMasterListSignatures(ml);
		if (!result) {
			System.err.println("ML verification failed");
		} else {
			System.out.println("ML verified");
		}		
	}

	private static void PKIDemo() throws CertificateEncodingException, IOException, CRLException {

		KeyPair keyPair = KeyGenerator.getInstance().generateRSAPair(Constants.RSAKeyLength.RSA_2048.getValue());

		///////// create ca

		/*
		 * DNType dn = new DNType(); dn.setCommonName("rootca");
		 * dn.setOrganizationalUnit("test"); dn.setOrganization("dream");
		 * dn.setCountry("KR"); dn.buildDNString()
		 */

		Date validFrom = new Date();
		Date validTo = DateUtils.addYears(validFrom, 1);

		X509Certificate rootCA = CertDemo.issueCA("cn=rootca,ou=test,o=dream,c=KR", BigInteger.valueOf(1), keyPair,
				Constants.SigningAlgo.SHA256WITHRSA.getAlgo(), validFrom, validTo);

		FileUtils.saveFile("output/pki/rootca.der", rootCA.getEncoded());

		System.out.println(rootCA.toString());

		// ==========================================

		////////// issue end entity cert

		X509Certificate leafCert = CertDemo.issueCert("cn=leaf,ou=test,o=dream,c=KR", rootCA, keyPair.getPublic(),
				Constants.SigningAlgo.SHA256WITHRSA.getAlgo(), validFrom, validTo, keyPair.getPrivate());

		FileUtils.saveFile("output/pki/leaf.der", leafCert.getEncoded());

		System.out.println(leafCert.toString());
		// =====================================
		////////// issue cert from request
		// request
		CertificateRequestFactory reqFac = new CertificateRequestFactory();

		PKCS10CertificationRequest req = reqFac.createCertRequest("cn=leaf2,ou=test,o=dream,c=KR", keyPair.getPublic(),
				keyPair.getPrivate(), Constants.SigningAlgo.SHA256WITHRSA.getAlgo());

		X509Certificate leafCert2 = CertDemo.issueCert(rootCA, req, Constants.SigningAlgo.SHA256WITHRSA.getAlgo(),
				validFrom, validTo, keyPair.getPrivate());

		FileUtils.saveFile("output/pki/leaf2.der", leafCert2.getEncoded());

		System.out.println(leafCert.toString());

		// ======================================
		///// CRL
		CrlDemo crlDemo = new CrlDemo();
		// normal crl
		X509CRL crl = crlDemo.issueCrl(keyPair.getPrivate(), rootCA, Constants.SigningAlgo.SHA256WITHRSA.getAlgo(), 1,
				false);
		FileUtils.saveFile("output/pki/crl.crl", crl.getEncoded());
		// delta crl
		X509CRL deltaCrl = crlDemo.issueCrl(keyPair.getPrivate(), rootCA, Constants.SigningAlgo.SHA256WITHRSA.getAlgo(),
				1, true);
		FileUtils.saveFile("output/pki/deltaCrl.crl", deltaCrl.getEncoded());
	}
}
