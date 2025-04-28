"""
PHI detection patterns for HIPAA compliance.

This module defines regular expression patterns for detecting various types
of Protected Health Information (PHI) in accordance with HIPAA requirements.
"""

# Define PHI pattern categories for organization
PHI_PATTERN_CATEGORIES = {
    'name': ['FULL_NAME', 'FIRST_NAME', 'LAST_NAME'],
    'address': ['ADDRESS', 'ZIPCODE_US', 'CITY_STATE'],
    'date': ['DATE_FULL', 'DATE_SHORT', 'DATE_ISO'],
    'phone': ['PHONE_US', 'PHONE_INTL'],
    'email': ['EMAIL'],
    'id': ['MEDICAL_RECORD_NUMBER', 'HEALTH_PLAN_ID', 'ACCOUNT_NUMBER'],
    'ssn': ['SSN'],
    'medical_record': ['MEDICAL_RECORD_NUMBER', 'HEALTH_PLAN_ID', 'DEVICE_ID'],
    'age': ['AGE_YEARS'],
    'account': ['CREDIT_CARD', 'ACCOUNT_NUMBER'],
    'license': ['LICENSE_NUMBER'],
    'biometric': ['BIOMETRIC_ID'],
    'device': ['DEVICE_ID', 'DEVICE_SERIAL'],
    'vehicle': ['VIN', 'LICENSE_PLATE'],
    'ip': ['IP_ADDRESS'],
    'url': ['URL'],
    'generic': []  # Catch-all for misc patterns
}

# Define PHI patterns as simple regex strings
PHI_PATTERNS = {
    # Identifiers
    'SSN': r'\b(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d|7[012]))([ -]?)(?!00)\d\d\3(?!0000)\d{4}\b',
    'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'PHONE_US': r'\b(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
    'PHONE_INTL': r'\b\+(?:[0-9] ?){6,14}[0-9]\b',
    
    # Address components
    'ADDRESS': r'\b\d+\s+([A-Za-z]+\s+){1,3}(St(reet)?|Ave(nue)?|Rd|Road|Dr(ive)?|Pl(ace)?|Blvd|Boulevard|Ln|Lane|Way|Court|Ct|Circle|Cir|Terrace|Ter|Square|Sq|Highway|Route|Parkway|Pkwy)\b',
    'ZIPCODE_US': r'\b\d{5}(-\d{4})?\b',
    'CITY_STATE': r'\b[A-Z][a-z]+(?:[\s-][A-Z][a-z]+)*,\s+[A-Z]{2}\b',
    
    # Date formats
    'DATE_FULL': r'\b(0?[1-9]|1[0-2])[-/](0?[1-9]|[12]\d|3[01])[-/](19|20)\d{2}\b',
    'DATE_SHORT': r'\b(0?[1-9]|1[0-2])[-/](0?[1-9]|[12]\d|3[01])[-/]\d{2}\b',
    'DATE_ISO': r'\b(19|20)\d{2}[-/](0?[1-9]|1[0-2])[-/](0?[1-9]|[12]\d|3[01])\b',
    
    # Financial information
    'CREDIT_CARD': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
    'ACCOUNT_NUMBER': r'\b[Aa]ccount\s+[Nn]umber\s*[:# ]?\s*\d{8,12}\b',
    
    # Medical identifiers
    'MEDICAL_RECORD_NUMBER': r'\b(?:MR|MRN)[\s#:]?\d{5,10}\b',
    'HEALTH_PLAN_ID': r'\b[Hh]ealth\s+[Pp]lan\s+(?:[Ii][Dd]|[Nn]umber)\s*[:# ]?\s*\w{6,12}\b',
    'DEVICE_ID': r'\b(?:UDI|Device\s+ID)[\s#:]?\w{6,16}\b',
    'DEVICE_SERIAL': r'\b[Ss]erial\s+[Nn]umber\s*[:# ]?\s*\w{4,20}\b',
    
    # Names
    'FULL_NAME': r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b',
    'FIRST_NAME': r'\b[A-Z][a-z]{2,20}\b',
    'LAST_NAME': r'\b[A-Z][a-z]{2,20}\b',
    
    # Age
    'AGE_YEARS': r'\b(?:age|aged)\s*(?:\d{1,3})\s*(?:years?|yrs?)?\s*(?:old)?\b',
    
    # Biometric identifiers
    'BIOMETRIC_ID': r'\b[Bb]iometric\s+[Ii][Dd]\s*[:# ]?\s*\w{8,20}\b',
    
    # Vehicle identifiers
    'VIN': r'\b[A-HJ-NPR-Z0-9]{17}\b',
    'LICENSE_PLATE': r'\b[A-Z0-9]{1,3}[\s-]?[A-Z0-9]{3,5}\b',
    
    # Network identifiers
    'IP_ADDRESS': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    'URL': r'\bhttps?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?\b',
    
    # Other identifiers
    'LICENSE_NUMBER': r'\b[Ll]icense\s+[Nn]umber\s*[:# ]?\s*\w{6,10}\b',
}

# Add empty lists for any missing categories in PHI_PATTERN_CATEGORIES
for category in PHI_PATTERN_CATEGORIES:
    if category not in PHI_PATTERN_CATEGORIES:
        PHI_PATTERN_CATEGORIES[category] = []
        
# Add patterns to 'generic' if they're not in any category
for pattern_name in PHI_PATTERNS:
    is_categorized = False
    for category, patterns in PHI_PATTERN_CATEGORIES.items():
        if pattern_name in patterns:
            is_categorized = True
            break
    
    if not is_categorized:
        PHI_PATTERN_CATEGORIES['generic'].append(pattern_name)