package com.dreamsecurity.ca.x509.factory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.icao.CscaMasterList;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcDSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import com.dreamsecurity.ca.util.Constants;

import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

/**
 * Generate CSCA MasterList
 * 
 * @author dream
 *
 */
public class MasterListFactory {

	private static final Logger logger = LogManager.getLogger(MasterListFactory.class);

	/**
	 * Issue CMS CSCA Master List
	 * 
	 * @param MLSCert
	 *            Master List signer certificate
	 * @param MLSKey
	 *            Mater List signer private key
	 * @param CSCACert
	 *            CSCA Certificate
	 * @param certList
	 *            List of CSCA/Link certificates including own and other
	 *            countries
	 * @param signingAlgo
	 *            Signing algorithm
	 * 
	 * @return
	 */
	@SuppressWarnings("rawtypes")
	public byte[] createMasterListCMS(X509Certificate MLSCert, PrivateKey MLSKey, X509Certificate CSCACert,
			X509Certificate[] certList, String signingAlgo) {

		String pubkeyAlgorithm = MLSCert.getPublicKey().getAlgorithm();
		String certAlgorithm = "";

		if (signingAlgo == null || signingAlgo.isEmpty()) {
			if (pubkeyAlgorithm.equals(Constants.KeyAlgo.RSA.getValue())) {
				certAlgorithm = Constants.SigningAlgo.SHA256WITHRSA.getAlgo();
			} else if (pubkeyAlgorithm.equals(Constants.KeyAlgo.EC.getValue())) {
				certAlgorithm = Constants.SigningAlgo.SHA256WITHECDSA.getAlgo();
			} else if (pubkeyAlgorithm.equals(Constants.KeyAlgo.DSA.getValue())) {
				certAlgorithm = Constants.SigningAlgo.SHA256WITHDSA.getAlgo();
			} else {
				logger.warn(
						"Cannot determine Master List Signer public key algorithm, selecting default signing algo SHA256WITHRSA ");
				certAlgorithm = "SHA256WITHRSA";
			}
		} else {
			certAlgorithm = signingAlgo;
		}

		List<Certificate> list = new ArrayList<Certificate>();

		for (X509Certificate c : certList) {
			try {
				list.add(new X509CertificateHolder(c.getEncoded()).toASN1Structure());
			} catch (CertificateEncodingException | IOException e) {
				logger.error("Error in converting X509Certificate to X509CertificateHolder: " + e.getMessage());
				e.printStackTrace();
			}
		}

		CscaMasterList ml = new CscaMasterList(list.toArray(new Certificate[list.size()]));
		CMSTypedData message = null;

		try {
			logger.trace("Master List data : " + new java.math.BigInteger(1, ml.getEncoded()).toString(16));
		} catch (IOException e) {
			logger.trace("Error in printing master list data " + e.getMessage());
			e.printStackTrace();
		}

		try {
			message = new CMSProcessableByteArray(ICAOObjectIdentifiers.id_icao_cscaMasterList,
					ml.toASN1Primitive().getEncoded());
		} catch (IOException e) {
			logger.error("Error in creating CMSTypedData: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(certAlgorithm);

		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

		AsymmetricKeyParameter privateKeyParameter = null;
		try {
			privateKeyParameter = PrivateKeyFactory.createKey(MLSKey.getEncoded());
		} catch (IOException e) {
			logger.error("Error in decoding Master List Signer private key: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		BcContentSignerBuilder signBuilder = null;
		if (pubkeyAlgorithm.equals(Constants.KeyAlgo.RSA.getValue())) {
			signBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
		} else if (pubkeyAlgorithm.equals(Constants.KeyAlgo.EC.getValue())) {
			signBuilder = new BcECContentSignerBuilder(sigAlgId, digAlgId);
		} else if (pubkeyAlgorithm.equals(Constants.KeyAlgo.DSA.getValue())) {
			signBuilder = new BcDSAContentSignerBuilder(sigAlgId, digAlgId);
		} else {
			signBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
		}

		ContentSigner contentSigner = null;
		try {
			contentSigner = signBuilder.build(privateKeyParameter);
		} catch (OperatorCreationException e) {
			logger.error("Error in building ContentSigner from ContentSignerBuilder: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		DefaultSignedAttributeTableGenerator signedAttrGen = new DefaultSignedAttributeTableGenerator() {
			@Override
			protected Hashtable createStandardAttributeTable(Map parameters) {
				Hashtable std = super.createStandardAttributeTable(parameters);
				if (std.containsKey(CMSAttributes.cmsAlgorithmProtect)) {
					std.remove(CMSAttributes.cmsAlgorithmProtect);
				}
				return std;
			}
		};

		CMSSignedDataGenerator dataGenerator = new CMSSignedDataGenerator();

		ArrayList<X509Certificate> signerCertList = new ArrayList<X509Certificate>();
		signerCertList.add(MLSCert);
		signerCertList.add(CSCACert);

		try {

			Store certs = new JcaCertStore(signerCertList);

			// get subject key id
			ASN1Primitive skiPrimitive = JcaX509ExtensionUtils
					.parseExtensionValue(MLSCert.getExtensionValue(Extension.subjectKeyIdentifier.getId()));

			SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(skiPrimitive.getEncoded());

			dataGenerator.addCertificates(certs);
			dataGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
					new JcaDigestCalculatorProviderBuilder().setProvider(Constants.bc_provider).build())
							.setSignedAttributeGenerator(signedAttrGen).build(contentSigner, ski.getKeyIdentifier()));

		} catch (CertificateEncodingException | CMSException | OperatorCreationException | IOException e) {
			logger.error("Error in adding signer certificate chain: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		CMSSignedData signedData = null;
		try {
			signedData = dataGenerator.generate(message, true);

			logger.trace("Master List : " + new java.math.BigInteger(1, signedData.getEncoded()).toString(16));
		} catch (CMSException e) {
			logger.error("Error in generating signed data (Master List) " + e.getMessage());
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			logger.trace("Error in printing Master List " + e.getMessage());
			e.printStackTrace();
		}

		byte[] mlSignedData = null;
		
		try {
			mlSignedData = signedData.toASN1Structure().getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			logger.error("Error in getting encoded Master List");
			e.printStackTrace();
			return null;
		}
		
		return mlSignedData;
	}

	

	/**
	 * Issue PKCS#7 CSCA Master List
	 * 
	 * @param MLSCert
	 *            Master List signer certificate
	 * @param MLSKey
	 *            Mater List signer private key
	 * @param CSCACert
	 *            CSCA Certificate
	 * @param certList
	 *            List of CSCA/Link certificates including own and other
	 *            countries
	 * @param signingAlgo
	 *            Signing algorithm
	 * @return
	 */
	public byte[] createMasterListPKCS7(X509Certificate MLSCert, PrivateKey MLSKey, X509Certificate CSCACert,
			X509Certificate[] certList, String signingAlgo) {

		String pubkeyAlgorithm = MLSCert.getPublicKey().getAlgorithm();
		String certAlgorithm = "";

		if (signingAlgo == null || signingAlgo.isEmpty()) {
			if (pubkeyAlgorithm.equals(Constants.KeyAlgo.RSA.getValue())) {
				certAlgorithm = Constants.SigningAlgo.SHA256WITHRSA.getAlgo();
			} else if (pubkeyAlgorithm.equals(Constants.KeyAlgo.EC.getValue())) {
				certAlgorithm = Constants.SigningAlgo.SHA256WITHECDSA.getAlgo();
			} else if (pubkeyAlgorithm.equals(Constants.KeyAlgo.DSA.getValue())) {
				certAlgorithm = Constants.SigningAlgo.SHA256WITHDSA.getAlgo();
			} else {
				logger.warn(
						"Cannot determine Master List Signer public key algorithm, selecting default signing algo SHA256WITHRSA ");
				certAlgorithm = "SHA256WITHRSA";
			}
		} else {
			certAlgorithm = signingAlgo;
		}

		List<Certificate> list = new ArrayList<Certificate>();

		for (X509Certificate c : certList) {
			try {
				list.add(new X509CertificateHolder(c.getEncoded()).toASN1Structure());
			} catch (CertificateEncodingException | IOException e) {
				logger.error("Error in converting X509Certificate to X509CertificateHolder: " + e.getMessage());
				e.printStackTrace();
			}
		}

		CscaMasterList ml = new CscaMasterList(list.toArray(new Certificate[list.size()]));

		try {
			logger.trace("Master List data : " + new java.math.BigInteger(1, ml.getEncoded()).toString(16));
		} catch (IOException e) {
			logger.trace("Error in printing master list data " + e.getMessage());
			e.printStackTrace();
		}

		////////////
		// Data to sign
		byte[] dataToSign = null;
		try {
			dataToSign = ml.getEncoded();
		} catch (IOException e) {
			logger.error("Error in encoding tbs data: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		// compute signature
		Signature signature = null;
		byte[] sigData = null;
		try {
			signature = Signature.getInstance(certAlgorithm);
			signature.initSign(MLSKey);
			signature.update(dataToSign);
			sigData = signature.sign();
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			logger.error("Error in generating signature: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		PKCS7 p7 = null;
		try {
			// load X500Name
			X500Name xName = new X500Name(MLSCert.getSubjectDN().getName());
			// load serial number
			BigInteger serial = MLSCert.getSerialNumber();
			// load digest algorithm
			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(certAlgorithm);
			AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
			AlgorithmId digestAlgorithmId = new AlgorithmId(new ObjectIdentifier(digAlgId.getAlgorithm().toString()));
			// load signing algorithm
			AlgorithmId signAlgorithmId = new AlgorithmId(new ObjectIdentifier(sigAlgId.getAlgorithm().toString()));

			// Create SignerInfo:
			SignerInfo sInfo = new SignerInfo(xName, serial, digestAlgorithmId, signAlgorithmId, sigData);
			// Create ContentInfo:
			ContentInfo cInfo = new ContentInfo(
					new ObjectIdentifier(ICAOObjectIdentifiers.id_icao_cscaMasterList.toString()),
					new DerValue(DerValue.tag_OctetString, dataToSign));
			// Create PKCS7 Signed data
			p7 = new PKCS7(new AlgorithmId[] { digestAlgorithmId }, cInfo, certList, new SignerInfo[] { sInfo });

		} catch (IOException e) {
			logger.error("Error in siging tbs data: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		ByteArrayOutputStream encodedSignedData = null;
		try {

			// Write PKCS7 to byteArray
			encodedSignedData = new DerOutputStream();

			p7.encodeSignedData(encodedSignedData);

			logger.trace("Master List : " + new java.math.BigInteger(1, encodedSignedData.toByteArray()).toString(16));
		} catch (IOException e) {
			logger.trace("Error in printing Master List " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		return encodedSignedData.toByteArray();
	}

}
