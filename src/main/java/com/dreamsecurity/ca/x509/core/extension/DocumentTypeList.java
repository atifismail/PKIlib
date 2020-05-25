package com.dreamsecurity.ca.x509.core.extension;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.util.ASN1Dump;

/**
 * Class for ICAO X509 certificate extension. 
 * See ICAO MRTD Technical Report LDS and PKI Maintenance 1.0 or later for spec of this extension.
 * 
 * documentTypeList  EXTENSION  ::=  {
 *     SYNTAX DocumentTypeListSyntax
 *     IDENTIFIED BY id-icao-mrtd-security-extensions-documentTypeList}
 * DocumentTypeListSyntax ::= SEQUENCE {
 *   version DocumentTypeListVersion,
 *   docTypeList SET OF DocumentType }
 *
 * DocumentTypeListVersion ::= INTEGER {v0(0)}
 * 
 * -- Document Type as contained in MRZ, e.g. "P" or "ID" where a
 * -- single letter denotes all document types starting with that letter
 * DocumentType ::= PrintableString(1..2) 
 * 
 * @version $Id$
 */
public class DocumentTypeList {
    
    private static final Logger logger = LogManager.getLogger(DocumentTypeList.class);

    private boolean criticalFlag;	

	private String[] docTypeList;
	
	public DocumentTypeList() {
		this.criticalFlag = false;
	}
	
	/**
	 * @return flag indicating if the extension should be marked as critical or not.
	 */
	public boolean isCritical() {
		return criticalFlag;
	}

	/**
	 * @param flag indicating if the extension should be marked as critical or not.
	 */
	public void setCritical(boolean criticalFlag) {
		this.criticalFlag = criticalFlag;
	}	
	
	/**
	 * Method that initializes the CertificateExtension
	 * @param docTypeList doc types certificate is allowed to sign	 
	 */
	public void init(String[] docTypeList){
		this.docTypeList = docTypeList;		
	}    
        
    public ASN1Encodable compile() {                
        if(docTypeList.length == 0) {
        	logger.error("No DocumentTypeList to make a certificate extension");           
           return null;
        }
        
        ASN1EncodableVector vec = new ASN1EncodableVector();

        // version
        vec.add(new ASN1Integer(0));
        
        // Add SET OF DocumentType
        final ASN1Encodable[] dts = new ASN1Encodable[docTypeList.length];
        int i = 0;
        for (final String type : docTypeList) {
            dts[i++] = new DERPrintableString(type);
        }
        vec.add(new DERSet(dts)); // the DERSet constructor performs the DER normalization (i.e., it sorts the set)
        
        ASN1Object gn = new DERSequence(vec);
        logger.trace("Constructed DocumentTypeList: "+ ASN1Dump.dumpAsString(gn, true));        
        
        return gn;
	}
}