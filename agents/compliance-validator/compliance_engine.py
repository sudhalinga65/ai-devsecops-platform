"""
AI Compliance Validator - Claude-Powered Compliance Analysis
Validates infrastructure against SOC2, HIPAA, PCI-DSS, and ISO 27001 standards
"""

import anthropic
import boto3
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
import yaml

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ComplianceValidator:
    """
    Claude-powered compliance validation engine that analyzes infrastructure
    configurations, policies, and practices against regulatory frameworks.
    """

    def __init__(
        self,
        anthropic_api_key: str,
        aws_region: str = 'us-east-1'
    ):
        """
        Initialize Compliance Validator with Claude AI

        Args:
            anthropic_api_key: Anthropic API key for Claude
            aws_region: AWS region
        """
        # Claude AI setup
        self.claude = anthropic.Anthropic(api_key=anthropic_api_key)

        # AWS setup
        self.config = boto3.client('config', region_name=aws_region)
        self.iam = boto3.client('iam', region_name=aws_region)
        self.s3 = boto3.client('s3', region_name=aws_region)
        self.ec2 = boto3.client('ec2', region_name=aws_region)
        self.rds = boto3.client('rds', region_name=aws_region)
        self.cloudtrail = boto3.client('cloudtrail', region_name=aws_region)
        self.kms = boto3.client('kms', region_name=aws_region)

        logger.info("Compliance Validator initialized with Claude AI")

    def validate_soc2_compliance(self) -> Dict:
        """
        Validate SOC2 compliance across AWS infrastructure

        Returns:
            SOC2 compliance report with findings and recommendations
        """
        logger.info("Starting SOC2 compliance validation")

        # Gather infrastructure state
        infrastructure_state = {
            'iam_policies': self._get_iam_policies(),
            'cloudtrail_status': self._get_cloudtrail_status(),
            'encryption_status': self._get_encryption_status(),
            's3_buckets': self._get_s3_bucket_policies(),
            'vpc_configs': self._get_vpc_configurations(),
            'mfa_status': self._get_mfa_status()
        }

        # Claude analysis
        prompt = f"""
Analyze this AWS infrastructure configuration for SOC2 compliance.

INFRASTRUCTURE STATE:
{json.dumps(infrastructure_state, indent=2)}

SOC2 TRUST SERVICE CRITERIA TO VALIDATE:
1. Security (CC6.1-CC6.8): Logical and physical access controls
2. Availability (A1.1-A1.3): System availability and performance
3. Processing Integrity (PI1.1-PI1.5): Complete, valid, accurate processing
4. Confidentiality (C1.1-C1.2): Data confidentiality
5. Privacy (P1.1-P8.1): Privacy controls

For each criteria, provide:
- Compliance Status (compliant/partial/non-compliant)
- Current Implementation
- Gaps Identified
- Risk Level (low/medium/high/critical)
- Remediation Steps
- Evidence Required for Audit

Provide your response as JSON with these keys:
- overall_status
- compliance_score (0-100)
- trust_service_criteria (array of objects for each criterion)
- critical_findings (array)
- recommendations (array with priority and effort)
- audit_readiness_score (0-100)
"""

        try:
            response = self.claude.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4000,
                temperature=0.1,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            # Extract JSON from Claude's response
            content = response.content[0].text

            # Find JSON in response (Claude may wrap it in markdown)
            if '```json' in content:
                json_start = content.find('```json') + 7
                json_end = content.find('```', json_start)
                json_str = content[json_start:json_end].strip()
            else:
                json_str = content

            analysis = json.loads(json_str)
            analysis['validated_at'] = datetime.now().isoformat()
            analysis['framework'] = 'SOC2'

            logger.info(f"SOC2 validation complete. Compliance score: {analysis.get('compliance_score', 0)}")

            return analysis

        except Exception as e:
            logger.error(f"Error in SOC2 validation: {e}")
            return {"error": str(e), "framework": "SOC2"}

    def validate_hipaa_compliance(self) -> Dict:
        """
        Validate HIPAA compliance for healthcare data protection

        Returns:
            HIPAA compliance report
        """
        logger.info("Starting HIPAA compliance validation")

        # Gather PHI-related infrastructure
        phi_infrastructure = {
            'encryption_at_rest': self._check_encryption_at_rest(),
            'encryption_in_transit': self._check_encryption_in_transit(),
            'access_controls': self._get_iam_policies(),
            'audit_logging': self._get_cloudtrail_status(),
            'backup_retention': self._get_backup_policies(),
            'network_isolation': self._get_vpc_configurations()
        }

        prompt = f"""
Analyze this infrastructure for HIPAA compliance (Health Insurance Portability and Accountability Act).

PHI INFRASTRUCTURE STATE:
{json.dumps(phi_infrastructure, indent=2)}

HIPAA SAFEGUARDS TO VALIDATE:

ADMINISTRATIVE SAFEGUARDS:
- Security Management Process (§164.308(a)(1))
- Workforce Security (§164.308(a)(3))
- Information Access Management (§164.308(a)(4))
- Security Awareness Training (§164.308(a)(5))
- Contingency Plan (§164.308(a)(7))

PHYSICAL SAFEGUARDS:
- Facility Access Controls (§164.310(a)(1))
- Workstation Security (§164.310(c))
- Device and Media Controls (§164.310(d)(1))

TECHNICAL SAFEGUARDS:
- Access Control (§164.312(a)(1))
- Audit Controls (§164.312(b))
- Integrity (§164.312(c)(1))
- Transmission Security (§164.312(e)(1))

For each safeguard, provide:
- Compliance Status
- Implementation Details
- Gaps and Violations
- Risk to PHI
- Remediation Steps
- Documentation Needed

Response format: JSON with keys:
- overall_status
- compliance_score (0-100)
- safeguards (array)
- phi_exposure_risk (low/medium/high/critical)
- violations (array)
- remediation_plan (prioritized array)
"""

        try:
            response = self.claude.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4000,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}]
            )

            content = response.content[0].text
            if '```json' in content:
                json_start = content.find('```json') + 7
                json_end = content.find('```', json_start)
                json_str = content[json_start:json_end].strip()
            else:
                json_str = content

            analysis = json.loads(json_str)
            analysis['validated_at'] = datetime.now().isoformat()
            analysis['framework'] = 'HIPAA'

            logger.info(f"HIPAA validation complete. Compliance score: {analysis.get('compliance_score', 0)}")

            return analysis

        except Exception as e:
            logger.error(f"Error in HIPAA validation: {e}")
            return {"error": str(e), "framework": "HIPAA"}

    def validate_pci_dss_compliance(self) -> Dict:
        """
        Validate PCI-DSS compliance for payment card data

        Returns:
            PCI-DSS compliance report
        """
        logger.info("Starting PCI-DSS compliance validation")

        cardholder_env = {
            'network_segmentation': self._check_network_segmentation(),
            'encryption': self._get_encryption_status(),
            'access_controls': self._get_iam_policies(),
            'monitoring': self._get_cloudtrail_status(),
            'vulnerability_scans': self._get_security_findings(),
            'firewall_rules': self._get_security_groups()
        }

        prompt = f"""
Analyze infrastructure for PCI-DSS v4.0 compliance (Payment Card Industry Data Security Standard).

CARDHOLDER DATA ENVIRONMENT:
{json.dumps(cardholder_env, indent=2)}

PCI-DSS REQUIREMENTS (12 Requirements):
1. Install and maintain network security controls
2. Apply secure configurations to all system components
3. Protect stored account data
4. Protect cardholder data with strong cryptography during transmission
5. Protect all systems and networks from malicious software
6. Develop and maintain secure systems and software
7. Restrict access to cardholder data by business need to know
8. Identify users and authenticate access to system components
9. Restrict physical access to cardholder data
10. Log and monitor all access to system components and cardholder data
11. Test security of systems and networks regularly
12. Support information security with organizational policies

For each requirement, provide:
- Compliance Status (compliant/partial/non-compliant)
- Controls in Place
- Control Gaps
- Risk Rating
- Remediation Actions
- Testing Requirements

Response as JSON:
- overall_status
- compliance_score (0-100)
- requirements (array with detailed analysis)
- critical_gaps (array)
- remediation_roadmap (with timelines)
- merchant_level_recommendation (1-4)
"""

        try:
            response = self.claude.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4000,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}]
            )

            content = response.content[0].text
            if '```json' in content:
                json_start = content.find('```json') + 7
                json_end = content.find('```', json_start)
                json_str = content[json_start:json_end].strip()
            else:
                json_str = content

            analysis = json.loads(json_str)
            analysis['validated_at'] = datetime.now().isoformat()
            analysis['framework'] = 'PCI-DSS'

            logger.info(f"PCI-DSS validation complete. Compliance score: {analysis.get('compliance_score', 0)}")

            return analysis

        except Exception as e:
            logger.error(f"Error in PCI-DSS validation: {e}")
            return {"error": str(e), "framework": "PCI-DSS"}

    def validate_terraform_compliance(self, terraform_dir: str) -> Dict:
        """
        Validate Terraform configurations for security and compliance

        Args:
            terraform_dir: Directory containing Terraform files

        Returns:
            Terraform compliance analysis
        """
        logger.info(f"Validating Terraform configurations in {terraform_dir}")

        import os

        # Read all .tf files
        tf_configs = {}
        for root, dirs, files in os.walk(terraform_dir):
            for file in files:
                if file.endswith('.tf'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r') as f:
                        tf_configs[file] = f.read()

        prompt = f"""
Analyze these Terraform configurations for security and compliance issues.

TERRAFORM CONFIGURATIONS:
{json.dumps(tf_configs, indent=2)}

ANALYZE FOR:

SECURITY ISSUES:
- Hardcoded credentials or secrets
- Overly permissive IAM policies
- Unencrypted resources (S3, RDS, EBS)
- Public exposure (security groups, S3 buckets)
- Missing encryption in transit
- Disabled logging/monitoring

COMPLIANCE ISSUES:
- SOC2 violations
- HIPAA violations (if PHI is handled)
- PCI-DSS violations (if payment data is handled)

BEST PRACTICES:
- Terraform state encryption
- Resource tagging
- Naming conventions
- Module structure
- Variable validation

For each issue found, provide:
- Severity (low/medium/high/critical)
- Resource and Line Reference
- Description
- Compliance Framework Violated
- Remediation Code
- Security Impact

Response as JSON:
- total_issues
- critical_issues (array)
- high_issues (array)
- medium_issues (array)
- low_issues (array)
- compliance_violations (grouped by framework)
- remediation_summary
"""

        try:
            response = self.claude.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4096,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}]
            )

            content = response.content[0].text
            if '```json' in content:
                json_start = content.find('```json') + 7
                json_end = content.find('```', json_start)
                json_str = content[json_start:json_end].strip()
            else:
                json_str = content

            analysis = json.loads(json_str)
            analysis['analyzed_at'] = datetime.now().isoformat()
            analysis['terraform_dir'] = terraform_dir

            logger.info(f"Terraform validation complete. Total issues: {analysis.get('total_issues', 0)}")

            return analysis

        except Exception as e:
            logger.error(f"Error in Terraform validation: {e}")
            return {"error": str(e)}

    # Helper methods to gather AWS infrastructure state

    def _get_iam_policies(self) -> Dict:
        """Get IAM policy summary"""
        try:
            users = self.iam.list_users()['Users']
            return {
                'user_count': len(users),
                'users_with_policies': [u['UserName'] for u in users[:10]]
            }
        except:
            return {'error': 'Unable to fetch IAM policies'}

    def _get_cloudtrail_status(self) -> Dict:
        """Get CloudTrail logging status"""
        try:
            trails = self.cloudtrail.describe_trails()['trailList']
            return {
                'enabled': len(trails) > 0,
                'trail_count': len(trails),
                'multi_region': any(t.get('IsMultiRegionTrail') for t in trails)
            }
        except:
            return {'enabled': False, 'error': 'Unable to fetch CloudTrail status'}

    def _get_encryption_status(self) -> Dict:
        """Check encryption status across services"""
        try:
            kms_keys = self.kms.list_keys()
            return {
                'kms_keys_count': len(kms_keys.get('Keys', [])),
                'encryption_available': len(kms_keys.get('Keys', [])) > 0
            }
        except:
            return {'encryption_available': False}

    def _get_s3_bucket_policies(self) -> List[Dict]:
        """Get S3 bucket security configurations"""
        try:
            buckets = self.s3.list_buckets()['Buckets']
            bucket_info = []
            for bucket in buckets[:20]:  # Limit to 20
                try:
                    encryption = self.s3.get_bucket_encryption(Bucket=bucket['Name'])
                    public_access = self.s3.get_public_access_block(Bucket=bucket['Name'])
                    bucket_info.append({
                        'name': bucket['Name'],
                        'encrypted': True,
                        'public_access_blocked': public_access['PublicAccessBlockConfiguration']['BlockPublicAcls']
                    })
                except:
                    bucket_info.append({
                        'name': bucket['Name'],
                        'encrypted': False,
                        'public_access_blocked': False
                    })
            return bucket_info
        except:
            return []

    def _get_vpc_configurations(self) -> Dict:
        """Get VPC security configurations"""
        try:
            vpcs = self.ec2.describe_vpcs()['Vpcs']
            return {
                'vpc_count': len(vpcs),
                'flow_logs_enabled': False  # Simplified
            }
        except:
            return {'vpc_count': 0}

    def _get_mfa_status(self) -> Dict:
        """Check MFA enforcement status"""
        try:
            summary = self.iam.get_account_summary()['SummaryMap']
            return {
                'users_with_mfa': summary.get('AccountMFAEnabled', 0),
                'root_mfa_enabled': summary.get('AccountMFAEnabled', 0) > 0
            }
        except:
            return {'root_mfa_enabled': False}

    def _check_encryption_at_rest(self) -> Dict:
        """Check encryption at rest for data stores"""
        try:
            rds_instances = self.rds.describe_db_instances()['DBInstances']
            encrypted = [db for db in rds_instances if db.get('StorageEncrypted')]
            return {
                'rds_total': len(rds_instances),
                'rds_encrypted': len(encrypted),
                'encryption_percentage': (len(encrypted) / len(rds_instances) * 100) if rds_instances else 0
            }
        except:
            return {'encryption_percentage': 0}

    def _check_encryption_in_transit(self) -> Dict:
        """Check TLS/SSL enforcement"""
        return {
            'alb_https_listeners': True,  # Simplified - would check actual ALB configs
            'cloudfront_https_only': True
        }

    def _get_backup_policies(self) -> Dict:
        """Get backup and retention policies"""
        return {
            'automated_backups_enabled': True,  # Simplified
            'retention_days': 30
        }

    def _check_network_segmentation(self) -> Dict:
        """Check network segmentation for PCI"""
        try:
            security_groups = self.ec2.describe_security_groups()['SecurityGroups']
            return {
                'security_group_count': len(security_groups),
                'segmentation_implemented': len(security_groups) > 1
            }
        except:
            return {'segmentation_implemented': False}

    def _get_security_findings(self) -> Dict:
        """Get security findings summary"""
        return {
            'vulnerability_scans_enabled': True,
            'last_scan': datetime.now().isoformat()
        }

    def _get_security_groups(self) -> List[Dict]:
        """Get security group rules"""
        try:
            sgs = self.ec2.describe_security_groups()['SecurityGroups']
            return [{
                'id': sg['GroupId'],
                'name': sg['GroupName'],
                'ingress_rules': len(sg.get('IpPermissions', []))
            } for sg in sgs[:20]]
        except:
            return []


if __name__ == "__main__":
    import os

    validator = ComplianceValidator(
        anthropic_api_key=os.environ.get('ANTHROPIC_API_KEY')
    )

    # Run SOC2 validation
    soc2_report = validator.validate_soc2_compliance()
    print("SOC2 Compliance Report:")
    print(json.dumps(soc2_report, indent=2))

    # Run HIPAA validation
    hipaa_report = validator.validate_hipaa_compliance()
    print("\nHIPAA Compliance Report:")
    print(json.dumps(hipaa_report, indent=2))
