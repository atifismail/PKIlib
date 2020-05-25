
package com.dreamsecurity.ca.x509.core.extension;

import org.bouncycastle.asn1.x509.BasicConstraints;

/**
 * Certificate Basic Constraints extension
 * @author dream
 *
 */
public class BasicConstraintsType {

	private Boolean ca;
    private Integer pathLenConstraint;
    private Boolean isCritical;
    
	public BasicConstraintsType() {
		pathLenConstraint = -1;
		isCritical = true;
	}
	
	public Boolean isCA() {
        return ca;
    }

    public void setCA(Boolean value) {
        this.ca = value;
    }

    public Integer getPathLenConstraint() {
        return pathLenConstraint;
    }

    public void setPathLenConstraint(Integer value) {
        this.pathLenConstraint = value;
    }

    public boolean isCritical() {
        return isCritical;        
    }

    public void setCritical(Boolean value) {
        this.isCritical = value;
    }
    
    public BasicConstraints compile() {
    	if(this.isCA()) {
    		if(this.pathLenConstraint >= 0) {
    			return new BasicConstraints(this.getPathLenConstraint());
    		} else {
    			return new BasicConstraints(this.isCA());
    		}    		
    	} else {
    		return new BasicConstraints(this.isCA());
    	}
    }
}
