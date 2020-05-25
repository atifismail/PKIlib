package com.dreamsecurity.ca.x509.core.extension;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.ReasonFlags;

/**
 * Freshest CRL certificate extension
 * @author dream
 *
 */
public class FreshestCRLType {

	private Boolean critical;
		
	private class DPStruct{
		Integer type;
		String value;
		String issuer;
		ReasonFlags reason;
	};
	
	List<DPStruct> dpList;
	
	public static final int otherName                     = 0;
    public static final int rfc822Name                    = 1;
    public static final int dNSName                       = 2;
    public static final int x400Address                   = 3;
    public static final int directoryName                 = 4;
    public static final int ediPartyName                  = 5;
    public static final int uniformResourceIdentifier     = 6;
    public static final int iPAddress                     = 7;
    public static final int registeredID                  = 8;
    
    /* reason flags*/
    public static final int unused                  = (1 << 7);
    public static final int keyCompromise           = (1 << 6);
    public static final int cACompromise            = (1 << 5);
    public static final int affiliationChanged      = (1 << 4);
    public static final int superseded              = (1 << 3);
    public static final int cessationOfOperation    = (1 << 2);
    public static final int certificateHold         = (1 << 1);
    public static final int privilegeWithdrawn      = (1 << 0);
    public static final int aACompromise            = (1 << 15);
       
	public FreshestCRLType() {
		this.critical = false;
	
		dpList = new ArrayList<>();
	}
	
	public void addCrlDisPoint(String value, int type, String issuer, ReasonFlags reason) {
						
		DPStruct dp = new DPStruct();
		dp.type = type;
		dp.value = value;
		dp.issuer = issuer;
		dp.reason = reason;
		
		dpList.add(dp);
	}
	
	// reason, issuer can be null
	public CRLDistPoint compile() {		
				
		DistributionPoint[] dps = new DistributionPoint[dpList.size()];
		
		int i = 0;
				
		for (DPStruct dpStruct : dpList) {
			GeneralName gn = null;
			if (dpStruct.type == GeneralName.otherName || dpStruct.type == GeneralName.ediPartyName || dpStruct.type == GeneralName.x400Address) {
				continue;			
			} else {
				gn = new GeneralName(dpStruct.type, dpStruct.value);
			}

			GeneralNames gns = new GeneralNames(gn);
			DistributionPointName dpn = new DistributionPointName(gns);
			
			DistributionPoint dp = null;
			
			if(dpStruct.issuer == null) {
				dp = new DistributionPoint(dpn, dpStruct.reason, null);
			} else {
				dp = new DistributionPoint(dpn, dpStruct.reason, new GeneralNames(new GeneralName(new X500Name(dpStruct.issuer))));
			}				
					
			dps[i] = dp;
			i++;
		}
		return new CRLDistPoint(dps);
	}
	
	
	public Boolean getCritical() {
		return critical;
	}

	public void setCritical(Boolean critical) {
		this.critical = critical;
	}
}
