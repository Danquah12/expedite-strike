"""
compliance_data.py
Framework-Specific Questionnaires for the GRC Dashboard

Contains detailed dictionaries outlining specific controls, questions, enhancements, 
and evidence requirements for each of the 12 supported GRC frameworks.
"""

# ==============================================================================
# PCI-DSS v4
# ==============================================================================
PCI_ASSESSMENT = {
    "PCI-1": {
        "family": "Req 1", "title": "Network Security Controls",
        "enhancements": ["1.2.1 Firewall Configuration", "1.3.1 Network Segregation"],
        "questions": [
            "How are firewall rules reviewed and approved?",
            "Is the Cardholder Data Environment (CDE) strictly isolated from untrusted networks?",
            "Are default vendor passwords changed on all network devices?"
        ],
        "evidence": ["Firewall rule review logs", "Network topology diagrams", "Router configs"]
    },
    "PCI-3": {
        "family": "Req 3", "title": "Protect Stored Account Data",
        "enhancements": ["3.2.1 Do not store SAD", "3.5.1 Primary Account Number (PAN) Encryption"],
        "questions": [
            "Are Primary Account Numbers (PANs) rendered unreadable anywhere they are stored?",
            "Is Sensitive Authentication Data (SAD) permanently deleted after authorization?",
            "How are cryptographic keys managed and rotated?"
        ],
        "evidence": ["Cryptography policy", "Key management procedures", "Data retention policy"]
    },
    "PCI-8": {
        "family": "Req 8", "title": "Identify and Authenticate Access",
        "enhancements": ["8.3.1 Multi-Factor Authentication (MFA)", "8.3.6 Password Complexity"],
        "questions": [
            "Is Multi-Factor Authentication (MFA) required for all access into the CDE?",
            "Are unique user IDs assigned to all personnel with CDE access?",
            "Are passwords set to a minimum of 12 characters with complexity requirements?"
        ],
        "evidence": ["MFA configuration screenshots", "IAM policies", "Password setting configurations"]
    }
}

# ==============================================================================
# ISO 27001
# ==============================================================================
ISO_ASSESSMENT = {
    "A.5": {
        "family": "A.5", "title": "Information Security Policies",
        "enhancements": ["A.5.1 Policies for info security", "A.5.1.2 Review of policies"],
        "questions": [
            "Are information security policies defined, published, and communicated to employees?",
            "How often are these policies reviewed by management?",
            "Who holds explicit ownership of the ISMS and its policies?"
        ],
        "evidence": ["Approved Information Security Policy", "Management review meeting minutes"]
    },
    "A.8": {
        "family": "A.8", "title": "Asset Management",
        "enhancements": ["A.8.1.1 Inventory of assets", "A.8.2.1 Classification of info"],
        "questions": [
            "Is there a centrally managed inventory of all information assets?",
            "Are assets classified based on legal requirements, value, and criticality?",
            "Is there a defined media handling and disposal process?"
        ],
        "evidence": ["Asset inventory registry", "Data classification matrix", "Media destruction logs"]
    },
    "A.12": {
        "family": "A.12", "title": "Operations Security",
        "enhancements": ["A.12.2.1 Controls against malware", "A.12.3.1 Information backup"],
        "questions": [
            "Are anti-malware solutions deployed continuously across all endpoints and servers?",
            "Are regular data backups performed and tested in accordance with the backup policy?",
            "How are vulnerabilities managed and patched across the infrastructure?"
        ],
        "evidence": ["Antivirus deployment reports", "Backup schedules and test logs", "Patch management records"]
    }
}

# ==============================================================================
# NIST CSF 2.0
# ==============================================================================
NIST_CSF_ASSESSMENT = {
    "ID.AM": {
        "family": "Identify", "title": "Asset Management",
        "enhancements": ["ID.AM-01 Hardware Inventory", "ID.AM-02 Software Inventory"],
        "questions": [
            "Are hardware and software inventories actively maintained and reconciled?",
            "How is unauthorized hardware or software detected and restricted?",
            "Are assets prioritized based on their classification and business value?"
        ],
        "evidence": ["Hardware/Software inventory", "Asset discovery tool output"]
    },
    "PR.AC": {
        "family": "Protect", "title": "Identity Management and Access Control",
        "enhancements": ["PR.AC-01 Identity Management", "PR.AC-03 Least Privilege"],
        "questions": [
            "Are identities proofed and bound to credentials (e.g., MFA)?",
            "Is access governed by the principle of least privilege?",
            "How frequently are access rights reviewed and audited?"
        ],
        "evidence": ["Access review logs", "MFA deployment status", "IAM provisioning docs"]
    },
    "DE.CM": {
        "family": "Detect", "title": "Continuous Monitoring",
        "enhancements": ["DE.CM-01 Network Monitoring", "DE.CM-03 Malicious Code Detection"],
        "questions": [
            "Is the network continuously monitored to detect potential cybersecurity events?",
            "Are centralized logs analyzed (e.g., via SIEM) for anomalous activity?",
            "How are new threat intelligence signatures integrated into detection tools?"
        ],
        "evidence": ["SIEM monitoring dashboards", "IDS/IPS configuration", "Threat intel feed subscriptions"]
    }
}

# ==============================================================================
# NIST 800-53 R5 (Federal)
# ==============================================================================
NIST_FEDERAL_ASSESSMENT = {
    # ── 1. Access Control (AC) ────────────────────────────────────────────────
    "AC-2": {
        "family": "AC", "title": "Account Management",
        "enhancements": ["AC-2(1) Automated System Account Management", "AC-2(3) Disable Inactive Accounts", "AC-2(7) Role-Based Schemes", "AC-2(12) Account Monitoring"],
        "questions": [
            "How are new user accounts requested and approved?",
            "What process ensures accounts are disabled when users leave the organization?",
            "How are inactive accounts automatically disabled? [AC-2(3)]",
            "Is account provisioning automated through IAM tools? [AC-2(1)]",
            "How are privileged accounts monitored? [AC-2(12)]",
            "Is RBAC implemented for user roles? [AC-2(7)]"
        ],
        "evidence": ["IAM system configurations", "User account lists", "Access review reports"]
    },
    "AC-6": {
        "family": "AC", "title": "Least Privilege",
        "enhancements": ["AC-6(1) Privileged Accounts", "AC-6(5) Privileged Account Auditing", "AC-6(10) Prohibit Non-Privileged Users from Executing Privileged Functions"],
        "questions": [
            "How does the system enforce least privilege access?",
            "How are privileged accounts separated from standard user accounts? [AC-6(1)]",
            "Are administrative actions logged and monitored? [AC-6(5)]",
            "How do you prevent standard users from executing privileged commands? [AC-6(10)]"
        ],
        "evidence": ["Privileged account audit logs", "Role definitions", "Administrative access reports"]
    },
    # ── 2. Awareness and Training (AT) ────────────────────────────────────────
    "AT-2": {
        "family": "AT", "title": "Security Awareness Training",
        "enhancements": ["AT-2(2) Insider Threat Awareness", "AT-2(3) Social Engineering and Mining"],
        "questions": [
            "Is basic security awareness training provided to all system users upon hire and annually?",
            "Does training include recognizing social engineering and phishing attacks? [AT-2(3)]",
            "Is insider threat awareness integrated into the training programme? [AT-2(2)]",
            "How is training completion tracked and reported?"
        ],
        "evidence": ["Training completion records", "Training content/syllabus", "Phishing simulation results"]
    },
    # ── 3. Audit and Accountability (AU) ──────────────────────────────────────
    "AU-6": {
        "family": "AU", "title": "Audit Review, Analysis & Reporting",
        "enhancements": ["AU-6(1) Automated Review", "AU-6(3) Correlation", "AU-6(5) Centralized Management"],
        "questions": [
            "Is automated log analysis performed by SIEM tools? [AU-6(1)]",
            "Are logs correlated across systems to detect threats? [AU-6(3)]",
            "Are logs centrally managed and monitored? [AU-6(5)]"
        ],
        "evidence": ["SIEM dashboards", "Log correlation reports"]
    },
    # ── 4. Assessment, Authorization, and Monitoring (CA) ─────────────────────
    "CA-2": {
        "family": "CA", "title": "Control Assessments",
        "enhancements": ["CA-2(1) Independent Assessors", "CA-2(2) Specialized Assessments"],
        "questions": [
            "Are security controls assessed at a frequency consistent with the system's risk level?",
            "Are independent assessors used for control assessments? [CA-2(1)]",
            "Are vulnerability scanning, red team, or pen testing conducted as specialised assessments? [CA-2(2)]",
            "How are assessment results documented and tracked?"
        ],
        "evidence": ["Security Assessment Report (SAR)", "Assessment plan", "Assessor independence documentation"]
    },
    # ── 5. Configuration Management (CM) ──────────────────────────────────────
    "CM-2": {
        "family": "CM", "title": "Baseline Configuration",
        "enhancements": ["CM-2(2) Automation Support", "CM-2(7) Continuous Monitoring"],
        "questions": [
            "Are baseline configurations documented for all systems?",
            "Are configuration baselines automatically enforced through configuration tools? [CM-2(2)]",
            "Are systems continuously monitored for configuration drift? [CM-2(7)]"
        ],
        "evidence": ["STIG/CIS baseline documents", "Configuration management tool reports"]
    },
    # ── 6. Contingency Planning (CP) ──────────────────────────────────────────
    "CP-2": {
        "family": "CP", "title": "Contingency Plan",
        "enhancements": ["CP-2(1) Coordinate with Related Plans", "CP-2(3) Resume Mission/Business Functions"],
        "questions": [
            "Is a contingency plan developed and maintained for the system?",
            "Is the contingency plan coordinated with related plans (IR, COOP, DR)? [CP-2(1)]",
            "Does the plan identify essential missions and business functions for resumption? [CP-2(3)]",
            "Is the contingency plan tested at least annually?"
        ],
        "evidence": ["Contingency plan document", "BIA (Business Impact Analysis)", "DR test results"]
    },
    # ── 7. Identification and Authentication (IA) ─────────────────────────────
    "IA-2": {
        "family": "IA", "title": "Identification & Authentication (Org Users)",
        "enhancements": ["IA-2(1) MFA for Privileged Accounts", "IA-2(2) MFA for Network Access", "IA-2(8) Replay Resistant Authentication"],
        "questions": [
            "Is MFA required for privileged users? [IA-2(1)]",
            "Is MFA required for remote network access? [IA-2(2)]",
            "What authentication mechanisms prevent credential replay attacks? [IA-2(8)]",
            "How are user identities verified before account creation?"
        ],
        "evidence": ["MFA configuration", "Authentication logs", "Identity provider configurations"]
    },
    "IA-5": {
        "family": "IA", "title": "Authenticator Management",
        "enhancements": ["IA-5(1) Password Complexity", "IA-5(4) Protection of Authentication Secrets", "IA-5(7) Cryptographic Protection"],
        "questions": [
            "What are the password complexity requirements? [IA-5(1)]",
            "How are passwords stored and protected? [IA-5(4)]",
            "Are authentication credentials encrypted in transit and storage? [IA-5(7)]"
        ],
        "evidence": ["Password policy", "Credential storage configurations", "Encryption settings"]
    },
    # ── 8. Incident Response (IR) ─────────────────────────────────────────────
    "IR-4": {
        "family": "IR", "title": "Incident Handling",
        "enhancements": ["IR-4(1) Automated Incident Handling", "IR-4(4) Information Correlation"],
        "questions": [
            "Is an incident handling capability implemented for the system?",
            "Are automated mechanisms used to support the incident handling process? [IR-4(1)]",
            "Are incident information and individual incident responses correlated? [IR-4(4)]",
            "How are lessons learned from incidents incorporated into the response process?"
        ],
        "evidence": ["Incident response plan", "Incident tracking system", "Post-incident reports"]
    },
    # ── 9. Maintenance (MA) ───────────────────────────────────────────────────
    "MA-2": {
        "family": "MA", "title": "Controlled Maintenance",
        "enhancements": ["MA-2(2) Automated Maintenance Activities"],
        "questions": [
            "Is system maintenance scheduled, performed, documented, and reviewed?",
            "Are maintenance records retained for the system?",
            "Are maintenance tools inspected before use on the system?",
            "How is remote maintenance controlled and monitored?"
        ],
        "evidence": ["Maintenance logs", "Maintenance schedule", "Approved maintenance tools list"]
    },
    # ── 10. Media Protection (MP) ─────────────────────────────────────────────
    "MP-6": {
        "family": "MP", "title": "Media Sanitization",
        "enhancements": ["MP-6(1) Review/Approve/Track/Document/Verify", "MP-6(2) Equipment Testing"],
        "questions": [
            "Are media sanitized before disposal, release, or reuse?",
            "Is sanitization equipment tested at defined intervals? [MP-6(2)]",
            "Are sanitization actions tracked and documented? [MP-6(1)]",
            "What sanitization techniques are used (clear, purge, destroy)?"
        ],
        "evidence": ["Media sanitization records", "Certificate of destruction", "Sanitization equipment test logs"]
    },
    # ── 11. Physical and Environmental Protection (PE) ────────────────────────
    "PE-3": {
        "family": "PE", "title": "Physical Access Control",
        "enhancements": ["PE-3(1) System Access", "PE-3(2) Facility/Information System Boundaries"],
        "questions": [
            "How is physical access to the facility and system components controlled?",
            "Are physical access authorisations verified before granting access?",
            "Are physical access logs maintained and reviewed?",
            "How are visitors escorted and monitored within the facility?"
        ],
        "evidence": ["Physical access control system logs", "Visitor records", "Badge access reports"]
    },
    # ── 12. Planning (PL) ─────────────────────────────────────────────────────
    "PL-2": {
        "family": "PL", "title": "System Security Plan",
        "enhancements": ["PL-2(3) Plan/Coordinate with Other Organizational Entities"],
        "questions": [
            "Is a System Security Plan (SSP) developed and maintained?",
            "Does the SSP describe the system's authorization boundary, operational environment, and security controls?",
            "Is the SSP reviewed and updated at least annually?",
            "Is the SSP coordinated with other relevant organizational entities? [PL-2(3)]"
        ],
        "evidence": ["System Security Plan (SSP)", "SSP review/approval records", "Authorization boundary diagram"]
    },
    # ── 13. Program Management (PM) ───────────────────────────────────────────
    "PM-9": {
        "family": "PM", "title": "Risk Management Strategy",
        "enhancements": [],
        "questions": [
            "Is an organisation-wide risk management strategy developed and implemented?",
            "Does the strategy address risk tolerance, risk assessment methodology, and risk response?",
            "Is the risk management strategy reviewed and updated at defined intervals?",
            "How is executive leadership involved in risk management decisions?"
        ],
        "evidence": ["Risk management strategy document", "Risk tolerance statement", "Executive risk briefings"]
    },
    # ── 14. Personnel Security (PS) ───────────────────────────────────────────
    "PS-3": {
        "family": "PS", "title": "Personnel Screening",
        "enhancements": ["PS-3(1) Classified Information", "PS-3(3) Information Requiring Special Protective Measures"],
        "questions": [
            "Are individuals screened prior to being authorised access to the system?",
            "Are background investigations conducted appropriate to the risk designation of the position?",
            "Are rescreening activities performed at defined intervals?",
            "How are adverse screening results handled?"
        ],
        "evidence": ["Background check policy", "Screening completion records", "Position risk designations"]
    },
    # ── 15. PII Processing and Transparency (PT) — NEW in Rev 5 ──────────────
    "PT-2": {
        "family": "PT", "title": "Authority to Process PII",
        "enhancements": ["PT-2(1) Data Tagging", "PT-2(2) Automation"],
        "questions": [
            "Is the authority to process PII determined and documented?",
            "Are specific, explicit, and legitimate purposes for PII processing identified?",
            "Is processing of PII limited to only the documented and authorised purposes?",
            "How do you ensure compliance with applicable privacy legislation (GDPR, CCPA, etc.)?"
        ],
        "evidence": ["Privacy Impact Assessment (PIA)", "Authority to operate documentation", "Data Processing Agreements"]
    },
    # ── 16. Risk Assessment (RA) ──────────────────────────────────────────────
    "RA-5": {
        "family": "RA", "title": "Vulnerability Monitoring and Scanning",
        "enhancements": ["RA-5(2) Update Vulnerabilities to be Scanned", "RA-5(5) Privileged Access", "RA-5(11) Public Disclosure Programme"],
        "questions": [
            "Are vulnerability scans performed on the system at defined intervals?",
            "Are vulnerability scanning tools updated prior to each scan? [RA-5(2)]",
            "Are privileged access scans conducted to identify additional vulnerabilities? [RA-5(5)]",
            "How are vulnerability scan results analysed and remediated?"
        ],
        "evidence": ["Vulnerability scan reports", "Remediation tracking", "Scanning tool configurations"]
    },
    # ── 17. System and Services Acquisition (SA) ──────────────────────────────
    "SA-4": {
        "family": "SA", "title": "Acquisition Process",
        "enhancements": ["SA-4(1) Functional Properties", "SA-4(2) Design/Implementation Information", "SA-4(9) Functions/Ports/Protocols/Services"],
        "questions": [
            "Are security functional requirements included in acquisition contracts?",
            "Are design/implementation details required from developers? [SA-4(2)]",
            "Are required ports, protocols, and services identified in acquisitions? [SA-4(9)]",
            "How are third-party software components assessed for security?"
        ],
        "evidence": ["Acquisition contract security clauses", "Software Bill of Materials (SBOM)", "Vendor security assessments"]
    },
    # ── 18. System and Communications Protection (SC) ─────────────────────────
    "SC-7": {
        "family": "SC", "title": "Boundary Protection",
        "enhancements": ["SC-7(4) External Telecommunications Services", "SC-7(5) Deny by Default / Allow by Exception", "SC-7(8) Route Traffic to Proxy Servers"],
        "questions": [
            "Is the external boundary of the system monitored and controlled?",
            "Is a deny-all, permit-by-exception policy implemented at managed interfaces? [SC-7(5)]",
            "Are communication channels separated for management, data, and control? [SC-7(4)]",
            "How is outbound traffic filtered and monitored?"
        ],
        "evidence": ["Firewall ruleset documentation", "Network architecture diagrams", "Boundary device configurations"]
    },
    # ── 19. System and Information Integrity (SI) ─────────────────────────────
    "SI-2": {
        "family": "SI", "title": "Flaw Remediation",
        "enhancements": ["SI-2(2) Automated Flaw Remediation Status", "SI-2(3) Time to Remediate Flaws"],
        "questions": [
            "Are system flaws identified, reported, and corrected within defined time periods?",
            "Is automated flaw remediation status reporting in place? [SI-2(2)]",
            "Are benchmarks established for time to remediate by severity? [SI-2(3)]",
            "How are patches tested before deployment to production systems?"
        ],
        "evidence": ["Patch management records", "WSUS/SCCM reports", "Vulnerability remediation SLAs"]
    },
    # ── 20. Supply Chain Risk Management (SR) — NEW in Rev 5 ──────────────────
    "SR-2": {
        "family": "SR", "title": "Supply Chain Risk Management Plan",
        "enhancements": ["SR-2(1) Establish SCRM Team"],
        "questions": [
            "Is a supply chain risk management plan developed for the system?",
            "Does the plan address risks associated with the global supply chain?",
            "Is a cross-functional SCRM team established? [SR-2(1)]",
            "How are supply chain threats and vulnerabilities identified and mitigated?"
        ],
        "evidence": ["Supply chain risk management plan", "SCRM team charter", "Supplier risk assessments"]
    },
}

# ==============================================================================
# HIPAA
# ==============================================================================
HIPAA_ASSESSMENT = {
    "164.308": {
        "family": "Admin", "title": "Administrative Safeguards",
        "enhancements": ["164.308(a)(1) Security Management Process", "164.308(a)(5) Security Awareness Training"],
        "questions": [
            "Has a comprehensive risk analysis of ePHI been conducted?",
            "Are there documented sanctions for workforce members failing to comply with security policies?",
            "Is there a formal security awareness training program for all employees handling ePHI?"
        ],
        "evidence": ["Risk assessment report", "Sanction policy", "Training completion logs"]
    },
    "164.310": {
        "family": "Physical", "title": "Physical Safeguards",
        "enhancements": ["164.310(a)(1) Facility Access Controls", "164.310(d)(1) Device/Media Controls"],
        "questions": [
            "Are procedures in place to limit physical access to electronic information systems?",
            "How is the receipt, removal, and disposal of hardware containing ePHI governed?",
            "Are workstations configured to protect against unauthorized viewing of ePHI?"
        ],
        "evidence": ["Facility access logs", "Media disposal certificates", "Clean desk / Workstation policy"]
    },
    "164.312": {
        "family": "Tech", "title": "Technical Safeguards",
        "enhancements": ["164.312(a)(1) Access Control", "164.312(e)(1) Transmission Security"],
        "questions": [
            "Are unique user identifications assigned for tracking ePHI access?",
            "Is ePHI encrypted when transmitted over an open electronic network?",
            "Are systems configured to automatically log off users after a period of inactivity?"
        ],
        "evidence": ["Encryption configurations", "Session timeout settings", "Unique user ID inventory"]
    }
}

# ==============================================================================
# CIS Controls
# ==============================================================================
CIS_ASSESSMENT = {
    "CIS-1": {
        "family": "Control 1", "title": "Inventory of Enterprise Assets",
        "enhancements": ["1.1 Establish Asset Inventory", "1.2 Address Unauthorized Assets"],
        "questions": [
            "Do you maintain a detailed enterprise-wide inventory of all IT assets?",
            "Is the asset inventory updated dynamically via active scanning tools?",
            "Is there a process for identifying and isolating unauthorized network attachments?"
        ],
        "evidence": ["Asset management reports", "Active scanning tool configs"]
    },
    "CIS-3": {
        "family": "Control 3", "title": "Data Protection",
        "enhancements": ["3.1 Establish Data Management Process", "3.6 Encrypt Data on End-User Devices"],
        "questions": [
            "Is there a documented process outlining data classifications, retention, and disposal?",
            "Is full-disk encryption enforced on all end-user mobile devices and laptops?",
            "Are Data Loss Prevention (DLP) tools deployed to monitor sensitive data egress?"
        ],
        "evidence": ["Data classification policy", "MDM device encryption status", "DLP rulesets"]
    },
    "CIS-4": {
        "family": "Control 4", "title": "Secure Configuration",
        "enhancements": ["4.1 Establish Secure Configurations", "4.7 Manage Default Accounts"],
        "questions": [
            "Are secure baselines (e.g., CIS Benchmarks) applied to all enterprise systems?",
            "Are all default accounts and passwords disabled or immediately changed upon deployment?",
            "How often do you assess endpoints for configuration drift?"
        ],
        "evidence": ["CIS Benchmark compliance reports", "Configuration management console"]
    }
}

# ==============================================================================
# SOC 2 Type II
# ==============================================================================
SOC2_ASSESSMENT = {
    "CC1": {
        "family": "CC1", "title": "Control Environment",
        "enhancements": ["CC1.1 Integrity and Ethical Values", "CC1.2 Board of Directors Oversight"],
        "questions": [
            "Has management defined and communicated a code of conduct and ethical standards?",
            "Are background checks performed for all individuals with access to customer data?",
            "Is there an organizational structure delineating reporting lines and authorities?"
        ],
        "evidence": ["Code of conduct acknowledgments", "Background check policy", "Organizational chart"]
    },
    "CC6": {
        "family": "CC6", "title": "Logical and Physical Access",
        "enhancements": ["CC6.1 Logical Access Controls", "CC6.6 External Boundary Protection"],
        "questions": [
            "Are logical access controls implemented to restrict data access to authorized individuals?",
            "Are external network boundaries protected against unauthorized external connections?",
            "Are user access reviews conducted at least quarterly?"
        ],
        "evidence": ["Firewall architectures", "Access review matrices", "Logical access provisioning logs"]
    },
    "CC7": {
        "family": "CC7", "title": "System Operations",
        "enhancements": ["CC7.1 Monitoring for Anomalies", "CC7.3 Incident Response Process"],
        "questions": [
            "Are operations continuously monitored to detect deviations from established baselines?",
            "Is there a formal incident response process capable of mitigating detected anomalies?",
            "Does the entity document and investigate identified security events effectively?"
        ],
        "evidence": ["SOC monitoring SLAs", "Incident response standard operating procedures", "Post-incident reports"]
    }
}

# ==============================================================================
# GDPR
# ==============================================================================
GDPR_ASSESSMENT = {
    "Art-5": {
        "family": "Article 5", "title": "Principles Relating to Processing of PII",
        "enhancements": ["Art 5.1(f) Integrity and Confidentiality"],
        "questions": [
            "Is personal data processed lawfully, fairly, and transparently?",
            "Are data processing activities limited to the specified original purpose?",
            "How is the security, integrity, and confidentiality of personal data ensured?"
        ],
        "evidence": ["Data Protection Impact Assessments (DPIA)", "Privacy policy", "Data processing agreements"]
    },
    "Art-17": {
        "family": "Article 17", "title": "Right to Erasure (Right to be Forgotten)",
        "enhancements": ["Prompt erasure of personal data"],
        "questions": [
            "Can data subjects easily request the deletion of their personal information?",
            "Is there a technical mechanism to remove PII completely from active and backup storage?",
            "Are third-party processors notified when a data subject invokes erasure?"
        ],
        "evidence": ["Data subject request logs", "Data deletion workflows", "Vendor notification records"]
    },
    "Art-32": {
        "family": "Article 32", "title": "Security of Processing",
        "enhancements": ["Pseudonymisation and Encryption", "Restoring Availability"],
        "questions": [
            "Is pseudonymisation and/or encryption applied to protect personal data?",
            "Can the availability of personal data be quickly restored in the event of an incident?",
            "Is there a process for regularly testing the effectiveness of technical security measures?"
        ],
        "evidence": ["Encryption/Pseudonymisation standards", "Disaster recovery test results", "Penetration testing reports"]
    }
}

# ==============================================================================
# CMMC 2.0
# ==============================================================================
CMMC_ASSESSMENT = {
    "AC.L1": {
        "family": "AC", "title": "Access Control (Level 1)",
        "enhancements": ["AC.L1-3.1.1 Authorized Access Control", "AC.L1-3.1.2 Transaction & Function Control"],
        "questions": [
            "Is system access strictly limited to authorized users and devices?",
            "Are users limited to only the types of transactions they are specifically authorized for?",
            "Are external connections routed through approved organizational gateways?"
        ],
        "evidence": ["System authorization lists", "Role-based access matrix", "Network perimeter configs"]
    },
    "IR.L2": {
        "family": "IR", "title": "Incident Response (Level 2)",
        "enhancements": ["IR.L2-3.6.1 Incident Handling", "IR.L2-3.6.2 Incident Reporting"],
        "questions": [
            "Is an operational incident-handling capability established that covers prep, detection, analysis, and recovery?",
            "Are incidents tracked, documented, and reported to appropriate external authorities promptly?",
            "Is the incident response capability tested periodically?"
        ],
        "evidence": ["Incident response plan", "Reported incident tracker", "Tabletop exercise post-mortem"]
    },
    "SC.L2": {
        "family": "SC", "title": "System & Communications Protection (Level 2)",
        "enhancements": ["SC.L2-3.13.1 Boundary Protection", "SC.L2-3.13.8 Data in Transit"],
        "questions": [
            "Are communications monitored, controlled, and protected at external boundaries?",
            "Is FIPS-validated cryptography used to protect the confidentiality of CUI in transit?",
            "Do systems employ least functionality configured blocks against unauthorized code execution?"
        ],
        "evidence": ["FIPS validation certificates", "Firewall traffic policies", "Endpoint protection configurations"]
    }
}

# ==============================================================================
# NIS2
# ==============================================================================
NIS2_ASSESSMENT = {
    "Art-21.1": {
        "family": "Article 21", "title": "Cybersecurity Risk-Management Measures",
        "enhancements": ["Risk analysis and info system security policies", "Incident handling"],
        "questions": [
            "Has the entity established comprehensive cybersecurity risk-management measures approved by the management body?",
            "Are these policies proportionate to the risks posed to the network and information systems?",
            "Is there a robust crisis management and business continuity implementation?"
        ],
        "evidence": ["Management board approvals", "Risk management framework", "Crisis management playbook"]
    },
    "Art-21.2": {
        "family": "Article 21", "title": "Supply Chain Security",
        "enhancements": ["Supply chain security", "Security in acquisition"],
        "questions": [
            "Are security aspects systematically evaluated regarding relationships between the entity and its suppliers?",
            "Are vulnerabilities tied to individual direct suppliers actively assessed and mitigated?",
            "Do supplier contracts include mandatory cybersecurity requirements and incident reporting SLA?"
        ],
        "evidence": ["Vendor risk assessment framework", "Supplier contract templates", "Third-party audit results"]
    },
    "Art-23": {
        "family": "Article 23", "title": "Reporting Obligations",
        "enhancements": ["Early warning reporting", "Incident notification"],
        "questions": [
            "Is there a process to provide an early warning of significant incidents to the CSIRT within 24 hours?",
            "Can a full incident notification be securely delivered within 72 hours of awareness?",
            "Are procedures in place to produce a final report within one month of the incident declaration?"
        ],
        "evidence": ["Regulatory reporting SOP", "Communication plans", "Incident disclosure templates"]
    }
}

# ==============================================================================
# DORA
# ==============================================================================
DORA_ASSESSMENT = {
    "Ch-2": {
        "family": "Chapter 2", "title": "ICT Risk Management",
        "enhancements": ["ICT risk management framework", "Protection and prevention"],
        "questions": [
            "Is there an ICT risk management framework implemented and periodically reviewed by the management body?",
            "Are redundant capacities installed to ensure resilience against severe operational disruptions?",
            "Is least privilege robustly applied to all ICT assets?"
        ],
        "evidence": ["ICT Risk Management Strategy document", "Resilience capacity assessments"]
    },
    "Ch-3": {
        "family": "Chapter 3", "title": "ICT-Related Incident Management",
        "enhancements": ["Incident classification", "Reporting of major incidents"],
        "questions": [
            "Are ICT-related incidents accurately classified according to DORA criteria?",
            "Is there an established logging system specifically designed to document major incidents?",
            "Are initial, intermediate, and final reports submitted to the competent authorities on time?"
        ],
        "evidence": ["Incident classification matrix", "Incident logging tools", "Authority submission logs"]
    },
    "Ch-4": {
        "family": "Chapter 4", "title": "Digital Operational Resilience Testing",
        "enhancements": ["General testing requirements", "TLPT (Threat Led Penetration Testing)"],
        "questions": [
            "Is an operational resilience testing program executed at least yearly for critical ICT systems?",
            "Are Threat-Led Penetration Tests (TLPT) conducted on live production systems every three years?",
            "Are mitigation plans immediately implemented following the discovery of vulnerabilities during testing?"
        ],
        "evidence": ["Annual resilience test schedules", "TLPT engagements and results", "Vulnerability remediation tracking"]
    }
}

# ==============================================================================
# ISO 42001 (Artificial Intelligence System Management)
# ==============================================================================
ISO42001_ASSESSMENT = {
    "A.6": {
        "family": "A.6", "title": "AI Risk Management",
        "enhancements": ["A.6.1 AI risk assessment", "A.6.2 AI risk treatment"],
        "questions": [
            "Are AI-specific risks (e.g., bias, transparency, security) assessed prior to model deployment?",
            "Is there a documented risk treatment plan targeting vulnerabilities within the AI lifecycle?",
            "How frequently are AI models re-evaluated against new emergent risks?"
        ],
        "evidence": ["AI risk assessment reports", "Model validation metrics", "Risk treatment logs"]
    },
    "A.8": {
        "family": "A.8", "title": "Data and Information Management",
        "enhancements": ["A.8.1 Training data quality", "A.8.3 Data provenance"],
        "questions": [
            "Are the sources and provenance of all AI training and validation data thoroughly documented?",
            "Are mechanisms in place to assess the quality, bias, and representation of the training datasets?",
            "How is the privacy and security of the training data maintained?"
        ],
        "evidence": ["Data metadata catalogs", "Bias evaluation reports", "Data privacy configurations"]
    },
    "A.9": {
        "family": "A.9", "title": "AI System Operation",
        "enhancements": ["A.9.2 System transparency", "A.9.4 Continuous monitoring"],
        "questions": [
            "Are stakeholders provided sufficient transparency regarding the AI model's logic and decision-making limitations?",
            "Is continuous monitoring deployed to detect model drift or data drift in the production environment?",
            "Are mechanisms established for human oversight and override of AI outputs?"
        ],
        "evidence": ["Explainability (XAI) reports", "Model drift dashboards", "Human-in-the-loop procedures"]
    }
}

# ==============================================================================
# COMPLIANCE DICTIONARY EXPORT
# ==============================================================================
QUESTIONNAIRES_BY_FRAMEWORK = {
    "pci-dss":      PCI_ASSESSMENT,
    "iso27001":     ISO_ASSESSMENT,
    "nist-csf":     NIST_CSF_ASSESSMENT,
    "nist-800-53":  NIST_FEDERAL_ASSESSMENT,
    "hipaa":        HIPAA_ASSESSMENT,
    "cis":          CIS_ASSESSMENT,
    "soc2":         SOC2_ASSESSMENT,
    "gdpr":         GDPR_ASSESSMENT,
    "cmmc":         CMMC_ASSESSMENT,
    "nis2":         NIS2_ASSESSMENT,
    "dora":         DORA_ASSESSMENT,
    "iso42001":     ISO42001_ASSESSMENT,
}

# ==============================================================================
# ENTERPRISE COMPLIANCE CONTROL FRAMEWORK (Master Control List)
# ==============================================================================
MASTER_CONTROL_MATRIX = [
    # ── 1. Governance & Risk Management Controls ──────────────────────────────
    {"id": "GRC-01", "name": "Information Security Policy", "desc": "Maintain an approved information security policy, reviewed annually by leadership", "mappings": ["ISO 27001", "NIST CSF", "NIST 800-53", "SOC2", "CMMC"]},
    {"id": "GRC-02", "name": "Risk Management Program", "desc": "Documented risk assessment methodology and risk register maintained", "mappings": ["ISO 27001", "NIST CSF", "NIST 800-53", "SOC2", "CMMC"]},
    {"id": "GRC-03", "name": "Third-Party Risk Management", "desc": "Vendor risk assessment prior to onboarding and annual vendor reviews", "mappings": ["ISO 27001", "NIST CSF", "NIST 800-53", "SOC2", "CMMC"]},
    {"id": "GRC-04", "name": "Compliance Monitoring", "desc": "Continuous monitoring of regulatory obligations", "mappings": ["ISO 27001", "NIST CSF", "NIST 800-53", "SOC2", "CMMC"]},
    {"id": "GRC-05", "name": "Security Governance Committee", "desc": "Executive oversight of security program", "mappings": ["ISO 27001", "NIST CSF", "NIST 800-53", "SOC2", "CMMC"]},
    # ── 2. Identity & Access Management Controls ──────────────────────────────
    {"id": "IAM-01", "name": "Least Privilege", "desc": "Users granted minimum access required", "mappings": ["PCI-DSS", "NIST 800-53", "CIS", "CMMC"]},
    {"id": "IAM-02", "name": "Multi-Factor Authentication", "desc": "MFA required for admin access, remote access, and sensitive systems", "mappings": ["PCI-DSS", "NIST 800-53", "CIS", "CMMC"]},
    {"id": "IAM-03", "name": "Role Based Access Control (RBAC)", "desc": "Access based on user roles and business function", "mappings": ["PCI-DSS", "NIST 800-53", "CIS", "CMMC"]},
    {"id": "IAM-04", "name": "Account Lifecycle Management", "desc": "Joiner, Mover, Leaver processes formally defined and executed", "mappings": ["PCI-DSS", "NIST 800-53", "CIS", "CMMC"]},
    {"id": "IAM-05", "name": "Privileged Access Monitoring", "desc": "Logging and regular review of privileged account access", "mappings": ["PCI-DSS", "NIST 800-53", "CIS", "CMMC"]},
    # ── 3. Network Security Controls ──────────────────────────────────────────
    {"id": "NET-01", "name": "Network Segmentation", "desc": "Logical or physical separation of networks based on criticality", "mappings": ["PCI-DSS", "NIST 800-53", "CIS"]},
    {"id": "NET-02", "name": "Firewall Management", "desc": "Strict rule review, deep packet inspection, and perimeter protection", "mappings": ["PCI-DSS", "NIST 800-53", "CIS"]},
    {"id": "NET-03", "name": "IDS / IPS Monitoring", "desc": "Intrusion Detection and Prevention Systems actively monitored", "mappings": ["PCI-DSS", "NIST 800-53", "CIS"]},
    {"id": "NET-04", "name": "Zero Trust Network Access", "desc": "Never trust, always verify access approach regardless of location", "mappings": ["PCI-DSS", "NIST 800-53", "CIS"]},
    {"id": "NET-05", "name": "Secure VPN Access", "desc": "Point-to-point and end-user secure VPN tunneling with MFA", "mappings": ["PCI-DSS", "NIST 800-53", "CIS"]},
    # ── 4. Endpoint Security Controls ─────────────────────────────────────────
    {"id": "END-01", "name": "Endpoint Detection & Response (EDR)", "desc": "Active EDR tools deployed on all enterprise endpoints", "mappings": ["CIS", "NIST 800-53"]},
    {"id": "END-02", "name": "Anti-Malware Protection", "desc": "Next-generation antivirus actively monitored and updating", "mappings": ["CIS", "NIST 800-53"]},
    {"id": "END-03", "name": "Secure Configuration Baselines", "desc": "Implementation of CIS Benchmarks or STIGs on operating systems", "mappings": ["CIS", "NIST 800-53"]},
    {"id": "END-04", "name": "Patch Management", "desc": "Expeditious deployment of security patches for OS and software", "mappings": ["CIS", "NIST 800-53"]},
    {"id": "END-05", "name": "Device Encryption", "desc": "Full disk encryption (BitLocker/FileVault) on all mobile assets", "mappings": ["CIS", "NIST 800-53"]},
    # ── 5. Vulnerability Management Controls ──────────────────────────────────
    {"id": "VULN-01", "name": "Vulnerability Scanning", "desc": "Internal scans monthly, External scans quarterly (e.g. Nessus/Qualys)", "mappings": ["PCI-DSS", "NIST 800-53", "CIS"]},
    {"id": "VULN-02", "name": "Penetration Testing", "desc": "Annual pentest and after major infrastructure changes", "mappings": ["PCI-DSS", "NIST 800-53", "CIS"]},
    {"id": "VULN-03", "name": "Vulnerability Remediation", "desc": "Critical: 7 days, High: 30 days, Medium: 60 days", "mappings": ["PCI-DSS", "NIST 800-53", "CIS"]},
    {"id": "VULN-04", "name": "Threat Intelligence Monitoring", "desc": "Active consumption of IoCs, TTPs, and CVE advisories", "mappings": ["PCI-DSS", "NIST 800-53", "CIS"]},
    # ── 6. Application Security Controls ──────────────────────────────────────
    {"id": "APP-01", "name": "Secure SDLC", "desc": "Security embedded in the Software Development Life Cycle", "mappings": ["OWASP", "NIST 800-53", "PCI-DSS"]},
    {"id": "APP-02", "name": "Static Code Analysis (SAST)", "desc": "Automated scanning of source code during CI/CD", "mappings": ["OWASP", "NIST 800-53", "PCI-DSS"]},
    {"id": "APP-03", "name": "Dynamic Security Testing (DAST)", "desc": "Automated testing of compiled/running applications", "mappings": ["OWASP", "NIST 800-53", "PCI-DSS"]},
    {"id": "APP-04", "name": "Software Composition Analysis", "desc": "Tracking and scanning of third-party open-source libraries", "mappings": ["OWASP", "NIST 800-53", "PCI-DSS"]},
    {"id": "APP-05", "name": "API Security Controls", "desc": "Rate limiting, Schema validation, and WAF protection", "mappings": ["OWASP", "NIST 800-53", "PCI-DSS"]},
    # ── 7. Data Protection & Privacy Controls ─────────────────────────────────
    {"id": "DATA-01", "name": "Data Classification Policy", "desc": "Formal classification (e.g., Public, Internal, Confidential, Restricted)", "mappings": ["GDPR", "HIPAA", "PCI-DSS"]},
    {"id": "DATA-02", "name": "Encryption at Rest", "desc": "Databases, file shares, and object storage encrypted (AES-256)", "mappings": ["GDPR", "HIPAA", "PCI-DSS"]},
    {"id": "DATA-03", "name": "Encryption in Transit", "desc": "TLS 1.2+ for all data crossing boundaries", "mappings": ["GDPR", "HIPAA", "PCI-DSS"]},
    {"id": "DATA-04", "name": "Data Loss Prevention (DLP)", "desc": "Automated blocking of unauthorized data exfiltration", "mappings": ["GDPR", "HIPAA", "PCI-DSS"]},
    {"id": "DATA-05", "name": "Privacy Impact Assessments", "desc": "Review of new projects affecting personal data (e.g. DPIAs)", "mappings": ["GDPR", "HIPAA", "PCI-DSS"]},
    # ── 8. Logging & Monitoring Controls ──────────────────────────────────────
    {"id": "LOG-01", "name": "Centralized Logging", "desc": "All critical systems forward logs to a centralized repository", "mappings": ["SOC2", "NIST 800-53", "CIS"]},
    {"id": "LOG-02", "name": "SIEM Monitoring", "desc": "24/7 Security Information and Event Management correlation", "mappings": ["SOC2", "NIST 800-53", "CIS"]},
    {"id": "LOG-03", "name": "Security Event Alerting", "desc": "Automated triggers for immediate analyst review", "mappings": ["SOC2", "NIST 800-53", "CIS"]},
    {"id": "LOG-04", "name": "Log Retention Policy", "desc": "Typically 90 days hot, 1 year cold storage", "mappings": ["SOC2", "NIST 800-53", "CIS"]},
    {"id": "LOG-05", "name": "Insider Threat Monitoring", "desc": "UBA/UEBA to detect anomalous employee behavior", "mappings": ["SOC2", "NIST 800-53", "CIS"]},
    # ── 9. Incident Response Controls ─────────────────────────────────────────
    {"id": "IR-01", "name": "Incident Response Plan", "desc": "Formally documented and annually tested IRP", "mappings": ["NIST CSF", "SOC2", "ISO 27001"]},
    {"id": "IR-02", "name": "Security Incident Reporting", "desc": "Clear channels for employees to report anomalous activity", "mappings": ["NIST CSF", "SOC2", "ISO 27001"]},
    {"id": "IR-03", "name": "Digital Forensics Capability", "desc": "Tools and retainers in place for deep technical investigations", "mappings": ["NIST CSF", "SOC2", "ISO 27001"]},
    {"id": "IR-04", "name": "Incident Post-Mortem Analysis", "desc": "Required lessons-learned documentation following major events", "mappings": ["NIST CSF", "SOC2", "ISO 27001"]},
    # ── 10. Business Continuity & Disaster Recovery ───────────────────────────
    {"id": "BCDR-01", "name": "Disaster Recovery Plan", "desc": "Documented steps to restore IT services following a disaster", "mappings": ["ISO 27001", "SOC2"]},
    {"id": "BCDR-02", "name": "Backup & Recovery", "desc": "Immutable, offsite, and regularly tested backups", "mappings": ["ISO 27001", "SOC2"]},
    {"id": "BCDR-03", "name": "Recovery Time Objectives", "desc": "Formally defined RTOs and RPOs for critical systems", "mappings": ["ISO 27001", "SOC2"]},
    {"id": "BCDR-04", "name": "Annual DR Testing", "desc": "Failover exercises conducted at least once per year", "mappings": ["ISO 27001", "SOC2"]},
    # ── 11. Cloud Security Controls ───────────────────────────────────────────
    {"id": "CLD-01", "name": "Cloud Security Posture Management", "desc": "CSPM tools monitoring AWS/Azure/GCP for misconfigurations", "mappings": ["CIS", "NIST 800-53", "CMMC"]},
    {"id": "CLD-02", "name": "Cloud Identity Security", "desc": "Strict IAM controls for programmatic/API access to cloud resources", "mappings": ["CIS", "NIST 800-53", "CMMC"]},
    {"id": "CLD-03", "name": "Storage Encryption", "desc": "S3/Blob storage encrypted with customer-managed keys (CMK)", "mappings": ["CIS", "NIST 800-53", "CMMC"]},
    {"id": "CLD-04", "name": "Cloud Logging & Monitoring", "desc": "CloudTrail, VPC Flow Logs, etc., forwarded to SIEM", "mappings": ["CIS", "NIST 800-53", "CMMC"]},
    # ── 12. AI Governance Controls ────────────────────────────────────────────
    {"id": "AI-01", "name": "AI Risk Assessment", "desc": "Evaluation of model risks prior to deployment", "mappings": ["ISO 42001"]},
    {"id": "AI-02", "name": "AI Model Transparency", "desc": "Ensuring decisions made by AI systems are explainable", "mappings": ["ISO 42001"]},
    {"id": "AI-03", "name": "Bias Monitoring", "desc": "Testing models for discriminatory tracking or drift", "mappings": ["ISO 42001"]},
    {"id": "AI-04", "name": "AI Security Controls", "desc": "Protection against prompt injection and model poisoning", "mappings": ["ISO 42001"]},
    # ── 13. Financial & Payment Security ──────────────────────────────────────
    {"id": "PCI-01", "name": "Cardholder Data Protection", "desc": "Strict masking and securing of Primary Account Numbers", "mappings": ["PCI-DSS"]},
    {"id": "PCI-02", "name": "Secure Payment Processing", "desc": "End-to-end encryption or tokenization of payment flows", "mappings": ["PCI-DSS"]},
    {"id": "PCI-03", "name": "Network Segmentation for CDE", "desc": "Complete isolation of the Cardholder Data Environment", "mappings": ["PCI-DSS"]},
    {"id": "PCI-04", "name": "Quarterly ASV Scans", "desc": "External scans by an Approved Scanning Vendor", "mappings": ["PCI-DSS"]},
    # ── 14. EU Regulatory Controls ────────────────────────────────────────────
    {"id": "EU-01", "name": "Data Subject Rights", "desc": "Technical ability to support GDPR RTBF and access requests", "mappings": ["GDPR", "NIS2", "DORA"]},
    {"id": "EU-02", "name": "Breach Notification (72 hours)", "desc": "SOP for notifying Supervisory Authorities within required SLA", "mappings": ["GDPR", "NIS2", "DORA"]},
    {"id": "EU-03", "name": "Operational Resilience Testing", "desc": "Including Threat-Led Penetration Testing (TLPT)", "mappings": ["GDPR", "NIS2", "DORA"]},
    {"id": "EU-04", "name": "ICT Risk Management", "desc": "Executive accountability for Information & Communication Tech risks", "mappings": ["GDPR", "NIS2", "DORA"]},
]

# ==============================================================================
# NIST SP 800-53 Rev. 5 CONTROL CATALOG
# ==============================================================================
NIST_800_53_CATALOG = [
    # ── 1. Access Control (AC) ────────────────────────────────────────────────
    {"id": "AC-1", "family": "AC", "control": "Policy and Procedures", "desc": "Develop, document, and disseminate access control policy."},
    {"id": "AC-2", "family": "AC", "control": "Account Management", "desc": "Manage system accounts including activation, modification, and disabling."},
    {"id": "AC-3", "family": "AC", "control": "Access Enforcement", "desc": "Enforce approved authorizations for logical access to information."},
    {"id": "AC-4", "family": "AC", "control": "Information Flow Enforcement", "desc": "Enforce approved authorizations for controlling the flow of information."},
    {"id": "AC-5", "family": "AC", "control": "Separation of Duties", "desc": "Separate duties of individuals to prevent malevolent activity without collusion."},
    {"id": "AC-6", "family": "AC", "control": "Least Privilege", "desc": "Employ the principle of least privilege, allowing only authorized accesses."},
    {"id": "AC-7", "family": "AC", "control": "Unsuccessful Logon Attempts", "desc": "Enforce a limit of consecutive invalid logon attempts."},
    {"id": "AC-8", "family": "AC", "control": "System Use Notification", "desc": "Display an approved system use notification message or banner."},
    {"id": "AC-17", "family": "AC", "control": "Remote Access", "desc": "Establish and authorize remote access to the system."},
    {"id": "AC-18", "family": "AC", "control": "Wireless Access", "desc": "Establish and authorize wireless access to the system."},
    {"id": "AC-19", "family": "AC", "control": "Mobile Device Access", "desc": "Restrict and authorize the use of mobile devices."},
    {"id": "AC-20", "family": "AC", "control": "External Information Systems", "desc": "Establish terms and conditions for using external systems."},
    # ── 2. Awareness and Training (AT) ────────────────────────────────────────
    {"id": "AT-1", "family": "AT", "control": "Policy and Procedures", "desc": "Develop and disseminate awareness and training policy."},
    {"id": "AT-2", "family": "AT", "control": "Security Awareness Training", "desc": "Provide basic security awareness training to system users."},
    {"id": "AT-3", "family": "AT", "control": "Role-Based Security Training", "desc": "Provide role-based training to personnel with assigned security roles."},
    {"id": "AT-4", "family": "AT", "control": "Training Records", "desc": "Document and monitor individual information security training activities."},
    # ── 3. Audit and Accountability (AU) ──────────────────────────────────────
    {"id": "AU-1", "family": "AU", "control": "Policy and Procedures", "desc": "Develop and disseminate audit and accountability policy."},
    {"id": "AU-2", "family": "AU", "control": "Event Logging", "desc": "Identify the types of events that the system is capable of logging."},
    {"id": "AU-3", "family": "AU", "control": "Content of Audit Records", "desc": "Ensure audit records contain sufficient information (what, when, where, who)."},
    {"id": "AU-6", "family": "AU", "control": "Audit Review, Analysis, and Reporting", "desc": "Review and analyze system audit records for inappropriate activity."},
    {"id": "AU-8", "family": "AU", "control": "Time Stamps", "desc": "Use internal system clocks to generate time stamps for audit records."},
    {"id": "AU-9", "family": "AU", "control": "Protection of Audit Information", "desc": "Protect audit information and tools from unauthorized access."},
    {"id": "AU-11", "family": "AU", "control": "Audit Record Retention", "desc": "Retain audit records for the specified retention period."},
    {"id": "AU-12", "family": "AU", "control": "Audit Record Generation", "desc": "Provide audit record generation capability for the system."},
    # ── 4. Assessment, Authorization, and Monitoring (CA) ─────────────────────
    {"id": "CA-1", "family": "CA", "control": "Policy and Procedures", "desc": "Security assessment and authorization policy."},
    {"id": "CA-2", "family": "CA", "control": "Control Assessments", "desc": "Assess the security controls in the system."},
    {"id": "CA-3", "family": "CA", "control": "Information Exchange", "desc": "Approve and manage information exchange agreements."},
    {"id": "CA-5", "family": "CA", "control": "Plan of Action and Milestones", "desc": "Develop a POA&M to reduce or eliminate known vulnerabilities."},
    {"id": "CA-6", "family": "CA", "control": "Authorization", "desc": "Assign a senior official as the authorizing official for the system."},
    {"id": "CA-7", "family": "CA", "control": "Continuous Monitoring", "desc": "Develop a continuous monitoring strategy and implement it."},
    {"id": "CA-8", "family": "CA", "control": "Penetration Testing", "desc": "Conduct penetration testing on the system or system components."},
    # ── 5. Configuration Management (CM) ──────────────────────────────────────
    {"id": "CM-1", "family": "CM", "control": "Policy and Procedures", "desc": "Configuration management policy."},
    {"id": "CM-2", "family": "CM", "control": "Baseline Configuration", "desc": "Develop, document, and maintain a baseline configuration."},
    {"id": "CM-3", "family": "CM", "control": "Configuration Change Control", "desc": "Determine the types of changes that are configuration-controlled."},
    {"id": "CM-4", "family": "CM", "control": "Impact Analysis", "desc": "Analyze changes to the system to determine potential security impacts."},
    {"id": "CM-5", "family": "CM", "control": "Access Restrictions for Change", "desc": "Define and enforce access restrictions for configuration changes."},
    {"id": "CM-6", "family": "CM", "control": "Configuration Settings", "desc": "Establish and document configuration settings for IS components."},
    {"id": "CM-7", "family": "CM", "control": "Least Functionality", "desc": "Configure the system to provide only essential capabilities."},
    {"id": "CM-8", "family": "CM", "control": "System Component Inventory", "desc": "Develop and document an inventory of system components."},
    # ── 6. Contingency Planning (CP) ──────────────────────────────────────────
    {"id": "CP-1", "family": "CP", "control": "Policy and Procedures", "desc": "Contingency planning policy."},
    {"id": "CP-2", "family": "CP", "control": "Contingency Plan", "desc": "Develop a contingency plan for the system."},
    {"id": "CP-4", "family": "CP", "control": "Contingency Plan Testing", "desc": "Test the contingency plan to determine readiness and effectiveness."},
    {"id": "CP-6", "family": "CP", "control": "Alternate Storage Site", "desc": "Establish an alternate storage site including necessary agreements."},
    {"id": "CP-7", "family": "CP", "control": "Alternate Processing Site", "desc": "Establish an alternate processing site with agreements."},
    {"id": "CP-9", "family": "CP", "control": "System Backup", "desc": "Conduct backups of user-level information and system-level information."},
    {"id": "CP-10", "family": "CP", "control": "System Recovery", "desc": "Provide for recovery of the system after a disruption."},
    # ── 7. Identification and Authentication (IA) ─────────────────────────────
    {"id": "IA-1", "family": "IA", "control": "Policy and Procedures", "desc": "Identification and authentication policy."},
    {"id": "IA-2", "family": "IA", "control": "Identification and Authentication", "desc": "Uniquely identify and authenticate users or processes acting on their behalf."},
    {"id": "IA-4", "family": "IA", "control": "Identifier Management", "desc": "Manage system identifiers by receiving authorization to assign them."},
    {"id": "IA-5", "family": "IA", "control": "Authenticator Management", "desc": "Manage authenticators (e.g., passwords, tokens) comprehensively."},
    {"id": "IA-7", "family": "IA", "control": "Cryptographic Module Authentication", "desc": "Implement mechanisms for authentication to cryptographic modules."},
    # ── 8. Incident Response (IR) ─────────────────────────────────────────────
    {"id": "IR-1", "family": "IR", "control": "Policy and Procedures", "desc": "Incident response policy."},
    {"id": "IR-2", "family": "IR", "control": "Incident Response Training", "desc": "Provide incident response training to users consistent with assigned roles."},
    {"id": "IR-4", "family": "IR", "control": "Incident Handling", "desc": "Implement an incident handling capability for security incidents."},
    {"id": "IR-5", "family": "IR", "control": "Incident Monitoring", "desc": "Track and document system security incidents."},
    {"id": "IR-6", "family": "IR", "control": "Incident Reporting", "desc": "Report security incidents to designated authorities."},
    {"id": "IR-8", "family": "IR", "control": "Incident Response Plan", "desc": "Develop an incident response plan detailing preparation and response."},
    # ── 9. Maintenance (MA) ───────────────────────────────────────────────────
    {"id": "MA-1", "family": "MA", "control": "Policy and Procedures", "desc": "System maintenance policy."},
    {"id": "MA-2", "family": "MA", "control": "Controlled Maintenance", "desc": "Schedule, perform, document, and review records of maintenance."},
    {"id": "MA-3", "family": "MA", "control": "Maintenance Tools", "desc": "Approve, control, and monitor maintenance tools."},
    {"id": "MA-4", "family": "MA", "control": "Remote Maintenance", "desc": "Approve, control, and monitor remote maintenance and diagnostic activities."},
    {"id": "MA-6", "family": "MA", "control": "Timely Maintenance", "desc": "Obtain maintenance support and spare parts within defined time periods."},
    # ── 10. Media Protection (MP) ─────────────────────────────────────────────
    {"id": "MP-1", "family": "MP", "control": "Policy and Procedures", "desc": "Media protection policy."},
    {"id": "MP-2", "family": "MP", "control": "Media Access", "desc": "Restrict access to digital and non-digital media to authorized individuals."},
    {"id": "MP-4", "family": "MP", "control": "Media Storage", "desc": "Physically control and securely store media."},
    {"id": "MP-5", "family": "MP", "control": "Media Transport", "desc": "Protect and control media during transport outside of controlled areas."},
    {"id": "MP-6", "family": "MP", "control": "Media Sanitization", "desc": "Sanitize media prior to disposal, release out of organizational control, or reuse."},
    # ── 11. Physical and Environmental Protection (PE) ────────────────────────
    {"id": "PE-1", "family": "PE", "control": "Policy and Procedures", "desc": "Physical and environmental protection policy."},
    {"id": "PE-2", "family": "PE", "control": "Physical Access Authorizations", "desc": "Develop, approve, and maintain a list of individuals with authorized access."},
    {"id": "PE-3", "family": "PE", "control": "Physical Access Control", "desc": "Control physical access to organizational facilities."},
    {"id": "PE-6", "family": "PE", "control": "Monitoring Physical Access", "desc": "Monitor physical access to the facility to detect unauthorized physical access."},
    {"id": "PE-8", "family": "PE", "control": "Visitor Access Records", "desc": "Maintain visitor access records to the facility."},
    {"id": "PE-13", "family": "PE", "control": "Fire Protection", "desc": "Employ and maintain fire suppression and detection devices."},
    # ── 12. Planning (PL) ─────────────────────────────────────────────────────
    {"id": "PL-1", "family": "PL", "control": "Policy and Procedures", "desc": "Security planning policy."},
    {"id": "PL-2", "family": "PL", "control": "System Security Plan", "desc": "Develop a formal system security plan (SSP)."},
    {"id": "PL-4", "family": "PL", "control": "Rules of Behavior", "desc": "Establish and make readily available rules of behavior for system users."},
    {"id": "PL-8", "family": "PL", "control": "Security Architecture", "desc": "Develop a security architecture for the system."},
    # ── 13. Personnel Security (PS) ───────────────────────────────────────────
    {"id": "PS-1", "family": "PS", "control": "Policy and Procedures", "desc": "Personnel security policy."},
    {"id": "PS-2", "family": "PS", "control": "Position Risk Designation", "desc": "Assign a risk designation to all organizational positions."},
    {"id": "PS-3", "family": "PS", "control": "Personnel Screening", "desc": "Screen individuals prior to authorizing access to the system."},
    {"id": "PS-4", "family": "PS", "control": "Personnel Termination", "desc": "Upon termination, disable system access and retrieve authenticators/credentials."},
    {"id": "PS-6", "family": "PS", "control": "Access Agreements", "desc": "Ensure individuals sign appropriate access agreements prior to granting access."},
    # ── 14. Risk Assessment (RA) ──────────────────────────────────────────────
    {"id": "RA-1", "family": "RA", "control": "Policy and Procedures", "desc": "Risk assessment policy."},
    {"id": "RA-2", "family": "RA", "control": "Security Categorization", "desc": "Categorize the system and information processed, stored, and transmitted."},
    {"id": "RA-3", "family": "RA", "control": "Risk Assessment", "desc": "Conduct an assessment of risk, examining threats, vulnerabilities, and impacts."},
    {"id": "RA-5", "family": "RA", "control": "Vulnerability Monitoring and Scanning", "desc": "Monitor for vulnerabilities and perform vulnerability scanning."},
    {"id": "RA-7", "family": "RA", "control": "Risk Response", "desc": "Respond to findings from security assessments and ongoing monitoring."},
    # ── 15. System and Services Acquisition (SA) ──────────────────────────────
    {"id": "SA-1", "family": "SA", "control": "Policy and Procedures", "desc": "System and services acquisition policy."},
    {"id": "SA-3", "family": "SA", "control": "System Development Life Cycle", "desc": "Manage the system using a documented SDLC that incorporates security."},
    {"id": "SA-4", "family": "SA", "control": "Acquisition Process", "desc": "Include security requirements and/or security specifications in acquisitions."},
    {"id": "SA-8", "family": "SA", "control": "Security Engineering Principles", "desc": "Apply system security engineering principles in the specification and design."},
    {"id": "SA-11", "family": "SA", "control": "Developer Testing and Evaluation", "desc": "Require the developer to create a security test and evaluation plan."},
    {"id": "SA-15", "family": "SA", "control": "Development Process", "desc": "Require developers to document quality control processes for system development."},
    # ── 16. System and Communications Protection (SC) ─────────────────────────
    {"id": "SC-1", "family": "SC", "control": "Policy and Procedures", "desc": "System and communications protection policy."},
    {"id": "SC-7", "family": "SC", "control": "Boundary Protection", "desc": "Monitor and control communications at the external boundary of the system."},
    {"id": "SC-8", "family": "SC", "control": "Transmission Confidentiality", "desc": "Protect the confidentiality and integrity of transmitted information."},
    {"id": "SC-12", "family": "SC", "control": "Cryptographic Key Management", "desc": "Establish and manage cryptographic keys for cryptography employed within the system."},
    {"id": "SC-13", "family": "SC", "control": "Cryptographic Protection", "desc": "Implement cryptography in accordance with applicable federal laws and guidelines."},
    {"id": "SC-28", "family": "SC", "control": "Protection of Information at Rest", "desc": "Protect the confidentiality and integrity of information at rest."},
    # ── 17. System and Information Integrity (SI) ─────────────────────────────
    {"id": "SI-1", "family": "SI", "control": "Policy and Procedures", "desc": "System and information integrity policy."},
    {"id": "SI-2", "family": "SI", "control": "Flaw Remediation", "desc": "Identify, report, and correct system flaws."},
    {"id": "SI-3", "family": "SI", "control": "Malicious Code Protection", "desc": "Employ malicious code protection mechanisms at system entry and exit points."},
    {"id": "SI-4", "family": "SI", "control": "System Monitoring", "desc": "Monitor the system to detect attacks and indicators of potential attacks."},
    {"id": "SI-5", "family": "SI", "control": "Security Alerts and Advisories", "desc": "Receive IS security alerts/advisories and take appropriate actions."},
    {"id": "SI-7", "family": "SI", "control": "Software Integrity", "desc": "Detect unauthorized changes to software and information."},
    # ── 18. Supply Chain Risk Management (SR) ─────────────────────────────────
    {"id": "SR-1", "family": "SR", "control": "Policy and Procedures", "desc": "Supply chain risk management policy."},
    {"id": "SR-2", "family": "SR", "control": "Supply Chain Risk Management Plan", "desc": "Develop a supply chain risk management plan for the system."},
    {"id": "SR-3", "family": "SR", "control": "Supply Chain Controls", "desc": "Establish a process to identify and apply supply chain controls."},
    {"id": "SR-5", "family": "SR", "control": "Acquisition Strategies", "desc": "Use supply chain risk management concepts in acquisition strategies."},
    # ── 19. Program Management (PM) ───────────────────────────────────────────
    {"id": "PM-1", "family": "PM", "control": "Information Security Program Plan", "desc": "Develop and disseminate an organization-wide information security program plan."},
    {"id": "PM-5", "family": "PM", "control": "System Inventory", "desc": "Develop and maintain an inventory of the information systems in the organization."},
    {"id": "PM-9", "family": "PM", "control": "Risk Management Strategy", "desc": "Develop a comprehensive organization-wide risk management strategy."},
    {"id": "PM-11", "family": "PM", "control": "Mission/Business Process Definition", "desc": "Define and prioritize organizational missions and business processes."},
    # ── 20. PII Processing and Transparency (PT) ──────────────────────────────
    {"id": "PT-1", "family": "PT", "control": "Policy and Procedures", "desc": "Privacy policy regarding processing of PII."},
    {"id": "PT-2", "family": "PT", "control": "Authority to Process PII", "desc": "Determine and document the authority to process PII."},
    {"id": "PT-3", "family": "PT", "control": "Personally Identifiable Information Processing", "desc": "Identify and document the PII processed by the system and specific reasons."},
]
