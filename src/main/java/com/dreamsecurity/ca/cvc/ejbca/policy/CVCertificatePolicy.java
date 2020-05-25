package com.dreamsecurity.ca.cvc.ejbca.policy;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;

import org.ejbca.cvc.AccessRights;
import org.ejbca.cvc.AuthorizationRole;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCDiscretionaryDataTemplate;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ConstructionException;

import com.dreamsecurity.ca.util.Validity;

/**
 * Defines various properties of CVCertificate related to certificate body and signing etc
 * @author dream
 *
 */
public class CVCertificatePolicy {

	private Validity validity;
	private String signingAlgorithm;
	
	private CAReferenceField certificationAuthorityReference;
	private HolderReferenceField certificateHolderReference;
	private AuthorizationRole authRole;
	private AccessRights accessRights;
	private Collection<CVCDiscretionaryDataTemplate> extensions;
	
	private PublicKey publicKey;
	
	public CVCertificatePolicy() {
		 extensions = null;
	}
	
	public void setExtension(String oid, byte[] value) {
		if(extensions == null) {
			extensions = new ArrayList<CVCDiscretionaryDataTemplate>();
		}
		try {
			extensions.add(new CVCDiscretionaryDataTemplate(oid, value));
		} catch (ConstructionException e) {
			System.err.println("Error in creating extension: " + e.getMessage());
			e.printStackTrace();
			return;
		}		
	}
	
	public void setExtensions(Collection<CVCDiscretionaryDataTemplate> extensions) {
		if(extensions == null) {
			extensions = new ArrayList<CVCDiscretionaryDataTemplate>();
		}
		extensions.addAll(extensions);		
	}
	
	public Collection<CVCDiscretionaryDataTemplate> getExtensions() {
		return extensions;
	}
	
	public Validity getValidity() {
		return validity;
	}
	public void setValidity(Validity validity) {
		this.validity = validity;
	}
	public String getSigningAlgorithm() {
		return signingAlgorithm;
	}
	public void setSigningAlgorithm(String signingAlgorithm) {
		this.signingAlgorithm = signingAlgorithm;
	}

	public void setCertificationAuthorityReference(String countryCode, String holderMnemonic, String sequenceNumber) {
		this.certificationAuthorityReference = new CAReferenceField(countryCode, holderMnemonic,
				sequenceNumber);
	}

	public CAReferenceField getCertificationAuthorityReference() {
		return this.certificationAuthorityReference;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public PublicKey getPublicKey() {
		return this.publicKey;
	}

	public void setCertificateHolderReference(String countryCode, String holderMnemonic, String sequenceNumber) {
		this.certificateHolderReference = new HolderReferenceField(countryCode, holderMnemonic, sequenceNumber);
	}
	
	public HolderReferenceField getCertificateHolderReference() {
		return this.certificateHolderReference;
	}
	public AuthorizationRole getAuthRole() {
		return authRole;
	}
	public void setAuthRole(AuthorizationRole authRole) {
		this.authRole = authRole;
	}
	public AccessRights getAccessRights() {
		return accessRights;
	}
	public void setAccessRights(AccessRights accessRights) {
		this.accessRights = accessRights;
	}	
}
