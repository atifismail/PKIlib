package com.dreamsecurity.ca.cvc.bc;

import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.eac.CVCertificateRequest;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;
import org.bouncycastle.eac.EACCertificateRequestHolder;
import org.bouncycastle.eac.EACException;
import org.bouncycastle.eac.jcajce.JcaPublicKeyConverter;
import org.bouncycastle.eac.operator.EACSignatureVerifier;
import org.bouncycastle.eac.operator.jcajce.JcaEACSignatureVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class CVValidator {

	private static final Logger logger = LogManager.getLogger(CVValidator.class);
	
	public boolean verifyCertReqInnerSign(byte[] reqbyte) {
		
		CVCertificateRequest req = CVCertificateRequest.getInstance(reqbyte);

		JcaEACSignatureVerifierBuilder builder = new JcaEACSignatureVerifierBuilder()
				.setProvider(new BouncyCastleProvider());

		PublicKey pubKey = null;
		try {
			pubKey = new JcaPublicKeyConverter().setProvider(new BouncyCastleProvider()).getKey(req.getPublicKey());

			EACSignatureVerifier verifier = builder.build(req.getPublicKey().getUsage(), pubKey);

			EACCertificateRequestHolder reqHol = new EACCertificateRequestHolder(req);

			return reqHol.isInnerSignatureValid(verifier);
		
		} catch (InvalidKeySpecException | EACException | OperatorCreationException e) {
			logger.error("Error in verifying inner signature: " + e.getMessage());
			e.printStackTrace();			
		}

		return false;
	}

	public boolean verifyCertReqOuterSign(byte[] reqbyte, PublicKeyDataObject authPubKey) {
		
		CVCertificateRequest req = CVCertificateRequest.getInstance(reqbyte);

		JcaEACSignatureVerifierBuilder builder = new JcaEACSignatureVerifierBuilder()
				.setProvider(new BouncyCastleProvider());

		PublicKey pubKey = null;
		try {
			pubKey = new JcaPublicKeyConverter().setProvider(new BouncyCastleProvider()).getKey(authPubKey);

			EACSignatureVerifier verifier = builder.build(req.getPublicKey().getUsage(), pubKey);

			// verify outer signature
			OutputStream vOut = verifier.getOutputStream();

			// get cvc, auth ref from request
			ASN1ApplicationSpecific auth = ASN1ApplicationSpecific.getInstance(req.toASN1Primitive().getEncoded());
			ASN1Sequence seq = ASN1Sequence.getInstance(auth.getObject(BERTags.SEQUENCE));

			// cvc
			vOut.write(ASN1ApplicationSpecific.getInstance(seq.getObjectAt(0)).getEncoded(ASN1Encoding.DER));
			// auth ref
			vOut.write(ASN1ApplicationSpecific.getInstance(seq.getObjectAt(1)).getContents());
						
			vOut.close();

			return verifier.verify(req.getOuterSignature());							

		} catch (InvalidKeySpecException | EACException | OperatorCreationException | IOException e) {
			logger.error("Error in verifying outer signature: " + e.getMessage());
			e.printStackTrace();
		}

		return false;
	}

}
