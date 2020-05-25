package com.dreamsecurity.ca.x509.core.extension;

import java.util.Vector;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;

/**
 * Name Restriction: Appears only in ca, does not appear in the user certificate, 
 * and the name is restricted to both Subject and SubjeectAltertiveName
 * kick in. Can limit multiple naming such as Email, DNS, X509 DN, etc.
 * If the name in the user certificate (Subject and SubjeectAltertiveName) 
 * is found with the Name in the CA certificate
 * Constraints violates and directly believes that the certificate is invalid. 
 * Must meet the limitations of multiple different type naming in Name Constraints
 * NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees
 * OPTIONAL, excludedSubtrees [1] GeneralSubtrees OPTIONAL }
 * GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
 *  
 *  
 *  otherName                     = 0;
 *	rfc822Name                    = 1;
 *	dNSName                       = 2;
 *	x400Address                   = 3;
 *	directoryName                 = 4;
 *	ediPartyName                  = 5;
 *	uniformResourceIdentifier     = 6;
 *	iPAddress                     = 7;
 *	registeredID                  = 8;
 */

public class NameConstraintsType {

	private Boolean critical;
	private Vector<GeneralSubtree> permitted;
	private Vector<GeneralSubtree> excluded;
	
    public static final int otherName                     = 0;
    public static final int rfc822Name                    = 1;
    public static final int dNSName                       = 2;
    public static final int x400Address                   = 3;
    public static final int directoryName                 = 4;
    public static final int ediPartyName                  = 5;
    public static final int uniformResourceIdentifier     = 6;
    public static final int iPAddress                     = 7;
    public static final int registeredID                  = 8;
	
	public NameConstraintsType() {
		this.critical = false;
		
		permitted = new Vector<GeneralSubtree>(); // Allow list of names
		excluded = new Vector<GeneralSubtree>(); // Limit name list
	}	
	
	public void addPermittedName(int tag, String value) {
		// Add an allowed name
		GeneralName permitteedNcGn = new GeneralName(tag, value);
		GeneralSubtree permittedGsNcGn = new GeneralSubtree(permitteedNcGn, null, null);
		permitted.add(permittedGsNcGn);
	}
	
	public void addExcluededName(int tag, String value) {
		// Add a restriction name
		GeneralName excludedNcGn = new GeneralName(tag, value);
		GeneralSubtree excludedGsNcGn = new GeneralSubtree(excludedNcGn,null, null);
		excluded.add(excludedGsNcGn);
	}
	
	public NameConstraints compile() {
		return new NameConstraints(permitted.toArray(new GeneralSubtree[permitted.size()]), excluded.toArray(new GeneralSubtree[excluded.size()]));
	}
	
	public Boolean isCritical() {
		return critical;
	}
	
	public void setCritical(Boolean critical) {
		this.critical = critical;
	}		
}