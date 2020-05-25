package com.dreamsecurity.ca.cvc.bc.factory;

import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.eac.CVCertificateRequest;
import org.bouncycastle.asn1.eac.CertificateHolderReference;
import org.bouncycastle.asn1.eac.CertificationAuthorityReference;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;
import org.bouncycastle.eac.jcajce.JcaPublicKeyConverter;
import org.bouncycastle.eac.operator.EACSigner;
import org.bouncycastle.eac.operator.jcajce.JcaEACSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * Generate CVC Certificate request
 * @author dream
 *
 */
public class CVRequestFactory {

	private static final Logger logger = LogManager.getLogger(CVRequestFactory.class);
	

	/**
	 * Issue CVC certificate request
	 * @param holdRef Certificate Holder reference
	 * @param requestPrivateKey Certificate Holder private key
	 * @param requestPublicKey Certificate Holder public key
	 * @param signingAlgo Inner signing algorithm
	 * @param outerAuthPrivateKey Outer signing authrority/previous private key
	 * @param outerSigningAlgo Outer signing algorithm
	 * @param innterAuthRef Certificate body authority reference
	 * @param outerAuthRef Authentication date authority reference/previous certificate
	 * @return
	 */
	public CVCertificateRequest issueCVCertRequest(CertificateHolderReference holdRef, PrivateKey requestPrivateKey,
			PublicKey requestPublicKey, String signingAlgo, PrivateKey outerAuthPrivateKey, String outerSigningAlgo,
			CertificationAuthorityReference innterAuthRef, CertificationAuthorityReference outerAuthRef) {

		/////// inner/outer signer
		JcaEACSignerBuilder signerBuilder = new JcaEACSignerBuilder().setProvider(new BouncyCastleProvider());

		EACSigner innerSigner = null;
		EACSigner outerSigner = null;
		try {
			innerSigner = signerBuilder.build(signingAlgo, requestPrivateKey);
			outerSigner = signerBuilder.build(outerSigningAlgo, outerAuthPrivateKey);
		} catch (OperatorCreationException e) {
			logger.error("Error building signer: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		// convert public key
		PublicKeyDataObject pubKeyDO = new JcaPublicKeyConverter()
				.getPublicKeyDataObject(innerSigner.getUsageIdentifier(), requestPublicKey);

		ASN1EncodableVector asnVec = new ASN1EncodableVector();

		///////////// Certificate Body //////////

		// profile id
		ASN1ApplicationSpecific pId = new DERApplicationSpecific(EACTags.INTERCHANGE_PROFILE, new byte[] { 0 });
		asnVec.add(pId);

		// CAR
		//asnVec.add(new DERApplicationSpecific(EACTags.ISSUER_IDENTIFICATION_NUMBER, innterAuthRef.getEncoded()));

		// public key
		try {
			asnVec.add(new DERApplicationSpecific(false, EACTags.CARDHOLDER_PUBLIC_KEY, pubKeyDO));
		} catch (IOException e) {
			logger.error("Error in getting CardHolder public key: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		// CHR
		asnVec.add(new DERApplicationSpecific(EACTags.CARDHOLDER_NAME, holdRef.getEncoded()));
	 
		/*
		CertificateHolderAuthorization ca = null;
		try {
			ca = new CertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport,
					CertificateHolderAuthorization.CVCA | CertificateHolderAuthorization.RADG3
					| CertificateHolderAuthorization.RADG4);
			
			// add CHA
			asnVec.add(ca);
					
			// add effective date
			asnVec.add(new DERApplicationSpecific(
	                false, EACTags.APPLICATION_EFFECTIVE_DATE, new DEROctetString(new PackedDate(new Date()).getEncoding())));
			
			// add expire date
			asnVec.add(new DERApplicationSpecific(
	                false, EACTags.APPLICATION_EXPIRATION_DATE, new DEROctetString(new PackedDate(new Date()).getEncoding())));
		} catch (IOException e) {			
			logger.error("Error in adding attributes to CV Certificate body: " + e.getMessage());
			e.printStackTrace();
			return null;
		}*/	
		
		// create cert body
		ASN1ApplicationSpecific b = new DERApplicationSpecific(EACTags.CERTIFICATE_CONTENT_TEMPLATE, asnVec);

		// create cert body signature
		OutputStream vOut = innerSigner.getOutputStream();
		try {
			vOut.write(b.getEncoded(ASN1Encoding.DER));
			vOut.close();
		} catch (IOException e) {
			logger.error("Error in encoding CertificateBody: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		////////////// CV Certificate /////////////

		// add cert body
		asnVec = new ASN1EncodableVector();
		asnVec.add(b);

		ASN1ApplicationSpecific a = null;

		// add cert body signature
		try {
			asnVec.add(new DERApplicationSpecific(false, EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP,
					new DEROctetString(innerSigner.getSignature())));
		} catch (IOException e) {
			logger.error("Error in encoding CertificateBody signature: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		// cv cert
		ASN1ApplicationSpecific cvc = new DERApplicationSpecific(EACTags.CARDHOLDER_CERTIFICATE, asnVec);

		////////////// Authentication /////////////

		// create cv cert signature
		vOut = outerSigner.getOutputStream();
		try {
			vOut.write(cvc.getEncoded(ASN1Encoding.DER));
			vOut.write(outerAuthRef.getEncoded());
			vOut.close();
		} catch (IOException e) {
			logger.error("Error in encoding cv certificate: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		// creating authen data
		asnVec = new ASN1EncodableVector();

		asnVec.add(cvc); // add cv cert

		asnVec.add(new DERApplicationSpecific(EACTags.ISSUER_IDENTIFICATION_NUMBER, outerAuthRef.getEncoded())); /* add CAR */
		try {
			asnVec.add(new DERApplicationSpecific(false, EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP,
					new DEROctetString(outerSigner.getSignature())));
		} catch (IOException e) {
			logger.error("Error in encoding outer signature: " + e.getMessage());
			e.printStackTrace();
		} /* add signature */

		a = new DERApplicationSpecific(EACTags.AUTHENTIFICATION_DATA, asnVec);

		return CVCertificateRequest.getInstance(a);
	}
}
