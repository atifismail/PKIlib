package com.dreamsecurity.ca.example.cvc.ejbca;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.HolderReferenceField;

import com.dreamsecurity.ca.cvc.ejbca.factory.CVCertificateFactory;
import com.dreamsecurity.ca.cvc.ejbca.factory.CVRequestFactory;
import com.dreamsecurity.ca.cvc.ejbca.policy.CVCertificatePolicy;
import com.dreamsecurity.ca.util.Constants;
import com.dreamsecurity.ca.util.Constants.ValidityType;
import com.dreamsecurity.ca.util.KeyGenerator;
import com.dreamsecurity.ca.util.Validity;

/**
 * Example for how to generate Ejbca CVC certificates
 * @author dream
 *
 */
public class CvcDemo {

	public static CVCertificate issueDVCert(String CA_COUNTRY_CODE, String CA_HOLDER_MNEMONIC, String CA_SEQUENCE_NO,
			String DV_COUNTRY_CODE, String DV_HOLDER_MNEMONIC, String DV_SEQUENCE_NO) throws IOException {

		KeyPair kp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());
		KeyPair cvcakp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());

		return issueCert(kp.getPublic(), new HolderReferenceField("KR", "DVCA", "00001"),
				new CAReferenceField("KR", "CVCA", "00001"), AuthorizationRoleEnum.DV_D, cvcakp.getPrivate());
	}

	public static CVCertificate issueISCert(String DV_COUNTRY_CODE, String DV_HOLDER_MNEMONIC, String DV_SEQUENCE_NO,
			String IS_COUNTRY_CODE, String IS_HOLDER_MNEMONIC, String IS_SEQUENCE_NO) throws IOException {

		KeyPair kp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());
		KeyPair dvkp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());

		return issueCert(kp.getPublic(), new HolderReferenceField("KR", "IS01", "00001"),
				new CAReferenceField("KR", "DVCA", "00001"), AuthorizationRoleEnum.IS, dvkp.getPrivate());

	}

	public static CVCAuthenticatedRequest issueDVRequest(String DV_COUNTRY_CODE, String DV_HOLDER_MNEMONIC,
			String DV_SEQUENCE_NO, String OTHER_CA_COUNTRY_CODE, String OTHER_CA_HOLDER_MNEMONIC,
			String OTHER_CA_SEQUENCE_NO, KeyPair authkp) throws IOException {

		KeyPair kp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());

		HolderReferenceField holdRef = new HolderReferenceField(DV_COUNTRY_CODE, DV_HOLDER_MNEMONIC,
				DV_SEQUENCE_NO);

		CAReferenceField authRef = new CAReferenceField(OTHER_CA_COUNTRY_CODE,
				OTHER_CA_HOLDER_MNEMONIC, OTHER_CA_SEQUENCE_NO);

		CVRequestFactory f = new CVRequestFactory();

		CVCAuthenticatedRequest req = f.issueCVCertRequest(holdRef, kp, 
				Constants.SigningAlgo.SHA1WITHECDSA.getAlgo(),
				authRef, authkp);

		System.out.println(req);

		return req;
	}

	public static CVCertificate issueCVCA(String CA_COUNTRY_CODE, String CA_HOLDER_MNEMONIC, String CA_SEQUENCE_NO)
			throws IOException {

		KeyPair kp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());

		return issueCert(kp.getPublic(), new HolderReferenceField(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO),
				new CAReferenceField(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO), AuthorizationRoleEnum.CVCA,
				kp.getPrivate());
	}

	public static CVCertificate issueCVCALink(String CA_COUNTRY_CODE, String CA_HOLDER_MNEMONIC, String CA_SEQUENCE_NO)
			throws IOException {

		KeyPair kp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());
		KeyPair newkp = KeyGenerator.getInstance().generateECPair(Constants.ECCurves.secp256r1.getValue());

		return issueCert(kp.getPublic(), new HolderReferenceField(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO),
				new CAReferenceField(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO), AuthorizationRoleEnum.CVCA,
				newkp.getPrivate());
	}

	public static CVCertificate issueCert(PublicKey pubKey, HolderReferenceField holdId, CAReferenceField authId,
			AuthorizationRoleEnum role, PrivateKey signingKey) {

		CVCertificatePolicy cp = new CVCertificatePolicy();

		cp.setCertificateHolderReference(holdId.getCountry(), holdId.getMnemonic(), holdId.getSequence());
		cp.setCertificationAuthorityReference(authId.getCountry(), authId.getMnemonic(), authId.getSequence());
		cp.setPublicKey(pubKey);
		cp.setAuthRole(role);
		cp.setAccessRights(AccessRightEnum.READ_ACCESS_DG3_AND_DG4);
		cp.setSigningAlgorithm(Constants.SigningAlgo.SHA1WITHECDSA.getAlgo());
		cp.setValidity(new Validity(ValidityType.YEAR, 1));
		cp.setExtension("1.2.3.4.5.6", "test".getBytes());

		CVCertificateFactory f = new CVCertificateFactory(cp);

		CVCertificate cert = f.issueCVCert(signingKey);

		System.out.println(cert);

		return cert;
	}

	public static boolean verifyInnerSign(byte[] derEncodedRequest) {

		CVRequestFactory f = new CVRequestFactory();
		CVCAuthenticatedRequest request = f.getInstance(derEncodedRequest);

		try {
			request.getRequest().verify(request.getRequest().getCertificateBody().getPublicKey(), Constants.bc_provider);
		} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException | NoSuchFieldException e) {
			System.err.println("Error in signature verification: " + e.getMessage());
			e.printStackTrace();
			return false;
		}	
		
		return true;
	}

	public static boolean verifyOuterSign(byte[] derEncodedRequest, PublicKey authPubKey) {

		CVRequestFactory f = new CVRequestFactory();
		CVCAuthenticatedRequest request = f.getInstance(derEncodedRequest);

		try {
			request.verify(authPubKey);
		} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			System.err.println("Error in signature verification: " + e.getMessage());
			e.printStackTrace();
			return false;
		}	
		
		return true;
	}
}
