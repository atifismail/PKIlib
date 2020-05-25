package com.dreamsecurity.ca.util;

import java.util.Date;

import org.apache.commons.lang3.time.DateUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.dreamsecurity.ca.util.Constants.ValidityType;


/**
 * Utility class for certificate validity period 
 * @author dream
 *
 */
public class Validity {
	
	private static final Logger logger = LogManager.getLogger(Validity.class);
	
	private Date notBefore;
	private Date notAfter;
	private ValidityType valitidyType;
	private int validityDuration;
	
	public Validity() {
		notAfter = notBefore = null;
		validityDuration = 1;
		valitidyType = Constants.ValidityType.YEAR;
	}
	
	public Validity(ValidityType validityType, int validityDuration) {
		
		notAfter = null;
		
		this.notBefore = new Date();
		
		this.valitidyType = validityType;
		this.validityDuration = validityDuration;
	}
	
	public Date getNotAfter() {
		
		if(notAfter == null) {
			if(this.valitidyType == ValidityType.YEAR) {
				return DateUtils.addYears(this.getNotBefore(), validityDuration);
			} else if (this.valitidyType == ValidityType.MONTH) {
				return DateUtils.addMonths(this.getNotBefore(), validityDuration);
			} else if (this.valitidyType == ValidityType.DAY) {
				return DateUtils.addDays(this.getNotBefore(), validityDuration);
			} else {
				logger.error("notAfter field is null or set a valid validity type");
				return null;
			}
		}
		
		return notAfter;
	}
	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}
	public Date getNotBefore() {
		
		if(notBefore == null) {
			return new Date();
		}
		
		return notBefore;
	}
	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}
	
	public ValidityType getValitidyType() {
		return valitidyType;
	}
	public void setValitidyType(ValidityType valitidyType) {
		this.valitidyType = valitidyType;
	}
	public int getValidityDuration() {
		return validityDuration;
	}
	public void setValidityDuration(int validityDuration) {
		this.validityDuration = validityDuration;
	}
	
}
