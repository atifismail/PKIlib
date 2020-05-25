package com.dreamsecurity.ca.example.x509.csca;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

import com.dreamsecurity.ca.x509.factory.MasterListFactory;

/**
 * Example for how to generate Master List 
 * @author dream
 *
 */
public class MasterList {

	public static byte[] createMasterListCMS(X509Certificate MLSCert, PrivateKey MLSKey, 
			X509Certificate CSCACert, X509Certificate[] certList) throws CertificateEncodingException, OperatorCreationException, IOException, CMSException {
		
		MasterListFactory mlf = new MasterListFactory();
		
		return mlf.createMasterListCMS(MLSCert, MLSKey, CSCACert, certList, "");		
	}
	
	public static byte[] createMasterListPKCS7(X509Certificate MLSCert, PrivateKey MLSKey, 
			X509Certificate CSCACert, X509Certificate[] certList) throws CertificateEncodingException, OperatorCreationException, IOException, CMSException {
		
		MasterListFactory mlf = new MasterListFactory();
		
		return mlf.createMasterListPKCS7(MLSCert, MLSKey, CSCACert, certList, "");		
	}
	
}
