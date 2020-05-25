package com.dreamsecurity.ca.example.cvc.bc;

import java.io.IOException;
import java.security.KeyPair;

import org.bouncycastle.asn1.eac.CVCertificate;
import org.bouncycastle.asn1.eac.CVCertificateRequest;
import org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import org.bouncycastle.asn1.eac.CertificateHolderReference;
import org.bouncycastle.asn1.eac.CertificationAuthorityReference;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;

import com.dreamsecurity.ca.cvc.bc.CVValidator;
import com.dreamsecurity.ca.cvc.bc.factory.CVCertificateFactory;
import com.dreamsecurity.ca.cvc.bc.factory.CVRequestFactory;
import com.dreamsecurity.ca.cvc.bc.policy.CVCertificatePolicy;
import com.dreamsecurity.ca.util.Constants;
import com.dreamsecurity.ca.util.Constants.ValidityType;
import com.dreamsecurity.ca.util.KeyGenerator;
import com.dreamsecurity.ca.util.Validity;

/**
 * Example for how to produce Bouncycastle CVC certificates
 * @author dream
 *
 */
public class CvcDemo {

	public static CVCertificate issueDVCert(String CA_COUNTRY_CODE, String CA_HOLDER_MNEMONIC, String CA_SEQUENCE_NO,
			String DV_COUNTRY_CODE, String DV_HOLDER_MNEMONIC, String DV_SEQUENCE_NO) throws IOException {

		KeyPair kp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());

		CVCertificatePolicy dvDef = new CVCertificatePolicy();
		dvDef.setCertificationAuthorityReference(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
		dvDef.setCertificateHolderReference(DV_COUNTRY_CODE, DV_HOLDER_MNEMONIC, DV_SEQUENCE_NO);
		dvDef.setCertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport,
				CertificateHolderAuthorization.DV_DOMESTIC | CertificateHolderAuthorization.RADG3
						| CertificateHolderAuthorization.RADG4);
		dvDef.setPublicKey(kp.getPublic());
		dvDef.setValidity(new Validity(ValidityType.MONTH, 3));

		CVCertificateFactory certGenerator = new CVCertificateFactory(dvDef);
		return certGenerator.issueCVCert(kp.getPrivate(), Constants.SigningAlgo.SHA1WITHECDSA.getAlgo());
	}

	public static CVCertificate issueISCert(String DV_COUNTRY_CODE, String DV_HOLDER_MNEMONIC, String DV_SEQUENCE_NO,
			String IS_COUNTRY_CODE, String IS_HOLDER_MNEMONIC, String IS_SEQUENCE_NO) throws IOException {

		KeyPair kp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());

		CVCertificatePolicy isDef = new CVCertificatePolicy();
		isDef.setCertificationAuthorityReference(DV_COUNTRY_CODE, DV_HOLDER_MNEMONIC, DV_SEQUENCE_NO);
		isDef.setCertificateHolderReference(IS_COUNTRY_CODE, IS_HOLDER_MNEMONIC, IS_SEQUENCE_NO);
		isDef.setCertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport,
				CertificateHolderAuthorization.IS | CertificateHolderAuthorization.RADG3
						| CertificateHolderAuthorization.RADG4);
		isDef.setPublicKey(kp.getPublic());
		isDef.setValidity(new Validity(ValidityType.MONTH, 3));

		CVCertificateFactory certGenerator = new CVCertificateFactory(isDef);

		return certGenerator.issueCVCert(kp.getPrivate(), Constants.SigningAlgo.SHA1WITHECDSA.getAlgo());

	}

	public static CVCertificateRequest issueDVRequest(String DV_COUNTRY_CODE, String DV_HOLDER_MNEMONIC,
			String DV_SEQUENCE_NO, String OTHER_CA_COUNTRY_CODE, String OTHER_CA_HOLDER_MNEMONIC,
			String OTHER_CA_SEQUENCE_NO) throws IOException {

		KeyPair kp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());

		CertificateHolderReference holdRef = new CertificateHolderReference(DV_COUNTRY_CODE, DV_HOLDER_MNEMONIC,
				DV_SEQUENCE_NO);

		CertificationAuthorityReference authRef = new CertificationAuthorityReference(OTHER_CA_COUNTRY_CODE,
				OTHER_CA_HOLDER_MNEMONIC, OTHER_CA_SEQUENCE_NO);

		CVRequestFactory certGenerator = new CVRequestFactory();

		CVCertificateRequest req = certGenerator.issueCVCertRequest(holdRef, kp.getPrivate(), kp.getPublic(),
				Constants.SigningAlgo.SHA1WITHECDSA.getAlgo(), kp.getPrivate(),
				Constants.SigningAlgo.SHA1WITHECDSA.getAlgo(), authRef, authRef);

		return req;
	}

	public static CVCertificate issueCVCA(String cA_COUNTRY_CODE, String cA_HOLDER_MNEMONIC, String cA_SEQUENCE_NO)
			throws IOException {

		KeyPair kp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());

		CVCertificatePolicy cvcaDef = new CVCertificatePolicy();
		cvcaDef.setCertificationAuthorityReference(cA_COUNTRY_CODE, cA_HOLDER_MNEMONIC, cA_SEQUENCE_NO);
		cvcaDef.setCertificateHolderReference(cA_COUNTRY_CODE, cA_HOLDER_MNEMONIC, cA_SEQUENCE_NO);
		cvcaDef.setCertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport,
				CertificateHolderAuthorization.CVCA | CertificateHolderAuthorization.RADG3
						| CertificateHolderAuthorization.RADG4);
		cvcaDef.setPublicKey(kp.getPublic());
		cvcaDef.setValidity(new Validity(ValidityType.YEAR, 3));

		CVCertificateFactory certGenerator = new CVCertificateFactory(cvcaDef);
		return certGenerator.issueCVCert(kp.getPrivate(), Constants.SigningAlgo.SHA1WITHECDSA.getAlgo());
	}

	public static CVCertificate issueCVCALink(String CA_COUNTRY_CODE, String CA_HOLDER_MNEMONIC, String CA_SEQUENCE_NO)
			throws IOException {

		KeyPair kp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());
		KeyPair newkp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());

		CVCertificatePolicy cvcaDef = new CVCertificatePolicy();
		cvcaDef.setCertificationAuthorityReference(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
		cvcaDef.setCertificateHolderReference(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
		cvcaDef.setCertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport,
				CertificateHolderAuthorization.CVCA | CertificateHolderAuthorization.RADG3
						| CertificateHolderAuthorization.RADG4);
		cvcaDef.setPublicKey(newkp.getPublic());
		cvcaDef.setValidity(new Validity(ValidityType.MONTH, 3));

		CVCertificateFactory certGenerator = new CVCertificateFactory(cvcaDef);
		return certGenerator.issueCVCert(kp.getPrivate(), Constants.SigningAlgo.SHA1WITHECDSA.getAlgo());
	}

	public static boolean verifyInnerSign(byte[] request) {
		
		CVValidator cvValid = new CVValidator();

		return cvValid.verifyCertReqInnerSign(request);

	}

	public static boolean verifyOuterSign(byte[] request, PublicKeyDataObject authPubKey) {

		CVValidator cvValid = new CVValidator();

		return cvValid.verifyCertReqOuterSign(request, authPubKey);

	}
}
