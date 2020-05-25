package com.dreamsecurity.ca.x509.core.extension;

import javax.security.auth.x500.X500Principal;

/**
 * Utility class to create certificate DN
 * @author dream
 *
 */
public class DNType {

	protected String organization;
	protected String organizationalUnit;
	protected String country;
	protected String state;
	protected String commonName;
	protected String distinguishedNameQualifier;
	protected String serialNumber;
	protected String locality;
	protected String title;
	protected String surname;
	protected String givenName;
	protected String pseudonym;
	protected String generationQualifier;
	protected String initials;

	/**
	 * @return possible object is {@link String }
	 * 
	 */
	public String getOrganization() {
		return organization;
	}

	/**
	 * 
	 * @param value
	 *            allowed object is {@link String }
	 * 
	 */
	public void setOrganization(String value) {
		this.organization = value;
	}

	/**
	 * 
	 * @return possible object is {@link String }
	 * 
	 */
	public String getOrganizationalUnit() {
		return organizationalUnit;
	}

	/**
	 * 
	 * @param value
	 *            allowed object is {@link String }
	 * 
	 */
	public void setOrganizationalUnit(String value) {
		this.organizationalUnit = value;
	}

	/**
	 * 
	 * @return possible object is {@link String }
	 * 
	 */
	public String getCountry() {
		return country;
	}

	/**
	 * 
	 * @param value
	 *            allowed object is {@link String }
	 * 
	 */
	public void setCountry(String value) {
		this.country = value;
	}

	/**
	 * 
	 * @return possible object is {@link String }
	 * 
	 */
	public String getState() {
		return state;
	}

	/**
	 * 
	 * @param value
	 *            allowed object is {@link String }
	 * 
	 */
	public void setState(String value) {
		this.state = value;
	}

	/**
	 * 
	 * @return possible object is {@link String }
	 * 
	 */
	public String getCommonName() {
		return commonName;
	}

	/**
	 * 
	 * @param value
	 *            allowed object is {@link String }
	 * 
	 */
	public void setCommonName(String value) {
		this.commonName = value;
	}

	/**
	 * @return possible object is {@link String }
	 * 
	 */
	public String getDistinguishedNameQualifier() {
		return distinguishedNameQualifier;
	}

	/**
	 * @param value
	 *            allowed object is {@link String }
	 * 
	 */
	public void setDistinguishedNameQualifier(String value) {
		this.distinguishedNameQualifier = value;
	}

	/**
	 * 
	 * @return possible object is {@link String }
	 * 
	 */
	public String getSerialNumber() {
		return serialNumber;
	}

	/**
	 * 
	 * @param value
	 *            allowed object is {@link String }
	 * 
	 */
	public void setSerialNumber(String value) {
		this.serialNumber = value;
	}

	/**
	 * 
	 * @return possible object is {@link String }
	 * 
	 */
	public String getLocality() {
		return locality;
	}

	/**
	 * 
	 * @param value
	 *            allowed object is {@link String }
	 * 
	 */
	public void setLocality(String value) {
		this.locality = value;
	}

	/**
	 * 
	 * @return possible object is {@link String }
	 * 
	 */
	public String getTitle() {
		return title;
	}

	/**
	 * 
	 * @param value
	 *            allowed object is {@link String }
	 * 
	 */
	public void setTitle(String value) {
		this.title = value;
	}

	/**
	 * 
	 * @return possible object is {@link String }
	 * 
	 */
	public String getSurname() {
		return surname;
	}

	/**
	 * 
	 * @param value
	 *            allowed object is {@link String }
	 * 
	 */
	public void setSurname(String value) {
		this.surname = value;
	}

	/**
	 * 
	 * @return possible object is {@link String }
	 * 
	 */
	public String getGivenName() {
		return givenName;
	}

	/**
	 * 
	 * @param value
	 *            allowed object is {@link String }
	 * 
	 */
	public void setGivenName(String value) {
		this.givenName = value;
	}

	/**
	 * 
	 * @return possible object is {@link String }
	 * 
	 */
	public String getPseudonym() {
		return pseudonym;
	}

	/**
	 * 
	 * @param value
	 *            allowed object is {@link String }
	 * 
	 */
	public void setPseudonym(String value) {
		this.pseudonym = value;
	}

	/**
	 * 
	 * @return possible object is {@link String }
	 * 
	 */
	public String getGenerationQualifier() {
		return generationQualifier;
	}

	/**
	 * 
	 * @param value
	 *            allowed object is {@link String }
	 * 
	 */
	public void setGenerationQualifier(String value) {
		this.generationQualifier = value;
	}

	/**
	 * 
	 * @return possible object is {@link String }
	 * 
	 */
	public String getInitials() {
		return initials;
	}

	/**
	 * 
	 * @param value
	 *            allowed object is {@link String }
	 * 
	 */
	public void setInitials(String value) {
		this.initials = value;
	}

	/**
	 * Build the issuer or subject string based on the provided certificate
	 * definition
	 *
	 * @param {@link
	 * 			CertificateDefinition} input The certificate definition XML to
	 *            parse
	 * @param {@link
	 * 			boolean} issuer Whether to create an issuer or a subject
	 *            string
	 * @return {@link String} The issuer / subject string generated using the
	 *         {@link CertificateDefinition} data
	 */
	public String buildDNString() {
		String result = "";

		if (this.getCommonName() != null) {
			result += "CN=" + getCommonName() + ", ";		
		}
		if (this.getSerialNumber() != null) {
			result += "serialNumber=" + getSerialNumber() + ", ";
		}
		if (this.getInitials() != null) {
			result += "initials=" + getInitials() + ", ";
		}
		if (this.getTitle() != null) {
			result += "title=" + getTitle() + ", ";
		}
		
		if (this.getGivenName() != null) {
			result += "GN=" + getGivenName() + ", ";
		}
		if (this.getSurname() != null) {
			result += "SN=" + getSurname() + ", ";
		}		
		if (this.getDistinguishedNameQualifier() != null) {
			result += "dnQualifier=" + getDistinguishedNameQualifier() + ", ";
		}		
		if (this.getPseudonym() != null) {
			result += "pseudonym=" + getPseudonym() + ", ";
		}
		if (this.getGenerationQualifier() != null) {
			result += "generationQualifier=" + getGenerationQualifier() + ", ";
		}
		if (this.getOrganizationalUnit() != null) {
			result += "OU=" + getOrganizationalUnit() + ", ";
		}
		if (this.getOrganization() != null) {
			result += "O=" + getOrganization() + ", ";
		}
		if (this.getState() != null) {
			result += "ST=" + getState() + ", ";
		}
		if (this.getLocality() != null) {
			result += "L=" + getLocality() + ", ";
		}
		if (this.getCountry() != null) {
			result += "C=" + getCountry() + ", ";			
		}
		
		// remove the trailing comma
		result = result.substring(0, result.length() - 2);
		return result;
	}
	
	public X500Principal compile() {
		return new X500Principal(this.buildDNString());
	}
}
