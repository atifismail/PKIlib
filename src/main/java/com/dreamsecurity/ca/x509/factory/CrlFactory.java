package com.dreamsecurity.ca.x509.factory;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.dreamsecurity.ca.x509.core.CrlType;
import com.dreamsecurity.ca.x509.core.policy.CrlPolicy;

/**
 * Generate CRL according to given CRL policy
 * @author dream
 *
 */
public class CrlFactory {

	private static final Logger logger = LogManager.getLogger(CrlFactory.class);

	private CrlPolicy crlPolicy;

	/**
	 * Set CRL policy
	 * @param crlPolicy
	 */
	public CrlFactory(CrlPolicy crlPolicy) {
		this.crlPolicy = crlPolicy;
	}

	/**
	 * Issuer CRL
	 * @param signingKey Signer private Key
	 * @param issuerCert Signer X.509 Certificate
	 * @param issuingTime Issuance time
	 * @param nextUpdate Next CRL issuance time
	 * @param signAlgo CRL Signing algorithm
	 * @param crlNo CRL Number
	 * @param crlEntryList List of CrlType defining revocation info about certificate
	 * @return
	 */
	public X509CRL issueCrl(PrivateKey signingKey, X509Certificate issuerCert, Date issuingTime, Date nextUpdate,
			String signAlgo, int crlNo, List<CrlType> crlEntryList) {

		X509CRL crl = generateCrl(signingKey, issuerCert, issuingTime, nextUpdate, signAlgo, crlNo, crlEntryList, false, 0);

		return crl;
	}

	/**
	 * Issue delta CRL
	 * @param signingKey Signer private key
	 * @param issuerCert Signer X.509 certificate
	 * @param issuingTime Issuance time
	 * @param nextUpdate Next CRL issuance time
	 * @param signAlgo CRL Signing algorithm
	 * @param crlNo CRL Number 
	 * @param baseCrlNo Base CRL Number
	 * @param crlEntryList List of CrlType defining revocation info about certificate
	 * @return
	 */
	public X509CRL issueDeltaCrl(PrivateKey signingKey, X509Certificate issuerCert, Date issuingTime, Date nextUpdate,
			String signAlgo, int crlNo, int baseCrlNo, List<CrlType> crlEntryList) {

		X509CRL crl = generateCrl(signingKey, issuerCert, issuingTime, nextUpdate, signAlgo, crlNo, crlEntryList, true,
				baseCrlNo);

		return crl;
	}

	private X509CRL generateCrl(PrivateKey signingKey, X509Certificate issuerCert, Date issuingTime, Date nextUpdate,
			String signAlgo, int crlNo, List<CrlType> crlEntryList, boolean isDeltaCrl, int baseCrlNo) {

		X509CRL crl = null;

		JcaX509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(issuerCert, issuingTime);

		crlGen.setNextUpdate(nextUpdate);

		for (CrlType revInfo : crlEntryList) {
			crlGen.addCRLEntry(revInfo.getCertSerialNo(), revInfo.getRevocationDate(), revInfo.getReason());
		}

		if (crlPolicy.getAuthKeyId() != null) {
			try {
				crlGen.addExtension(Extension.authorityKeyIdentifier, false, crlPolicy.getAuthKeyId().compile());
			} catch (CertIOException e) {
				logger.error("Error in adding authorityKeyIdentifier extension: " + e.getMessage());
				e.printStackTrace();

				return null;
			}
		}

		if (crlPolicy.getIssuingDistributionPoint() != null) {
			try {
				crlGen.addExtension(Extension.issuingDistributionPoint, false,
						crlPolicy.getIssuingDistributionPoint().compile());
			} catch (CertIOException e) {
				logger.error("Error in adding issuingDistributionPoint extension: " + e.getMessage());
				e.printStackTrace();

				return null;
			}
		}

		if (crlPolicy.getFreshestCRLType() != null) {
			try {
				crlGen.addExtension(Extension.freshestCRL, false, crlPolicy.getFreshestCRLType().compile());
			} catch (CertIOException e) {
				logger.error("Error in adding freshestCRL extension: " + e.getMessage());
				e.printStackTrace();

				return null;
			}
		}

		if (crlPolicy.getExpiredCertsOnCRL() != null) {
			try {
				crlGen.addExtension(Extension.expiredCertsOnCRL, false, crlPolicy.getExpiredCertsOnCRL().compile());
			} catch (CertIOException e) {
				logger.error("Error in adding expiredCertOnCRL extension: " + e.getMessage());
				e.printStackTrace();

				return null;
			}
		}

		if (crlPolicy.getAia() != null) {
			try {
				crlGen.addExtension(Extension.authorityInfoAccess, false, crlPolicy.getAia().compile());
			} catch (CertIOException e) {
				logger.error("Error in adding authorityInfoAccess extension: " + e.getMessage());
				e.printStackTrace();

				return null;
			}
		}

		// crl no
		try {
			crlGen.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(crlNo)));
		} catch (CertIOException e) {
			logger.error("Error in adding CrlNumber extension: " + e.getMessage());
			e.printStackTrace();

			return null;
		}

		if (isDeltaCrl) {
			try {
				crlGen.addExtension(Extension.deltaCRLIndicator, true, new CRLNumber(BigInteger.valueOf(baseCrlNo)));
			} catch (CertIOException e) {
				logger.error("Error in adding Delta CRL extension: " + e.getMessage());
				e.printStackTrace();

				return null;
			}
		}

		ContentSigner signer;
		try {
			signer = new JcaContentSignerBuilder(signAlgo).build(signingKey);
		} catch (OperatorCreationException e) {
			logger.error("Error in building content signer: ", e.getMessage());
			e.printStackTrace();
			return null;
		}

		JcaX509CRLConverter converter = new JcaX509CRLConverter();
		converter.setProvider(new BouncyCastleProvider());
		try {
			crl = converter.getCRL(crlGen.build(signer));
		} catch (CRLException e) {
			logger.error("Error in generating CRL: " + e.getMessage());
			e.printStackTrace();
			return null;
		}

		return crl;
	}

	public CrlPolicy getCrlPolicy() {
		return crlPolicy;
	}

	public void setCrlPolicy(CrlPolicy crlPolicy) {
		this.crlPolicy = crlPolicy;
	}
}
