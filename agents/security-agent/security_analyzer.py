"""
AI Security Agent - GPT-4 Powered Vulnerability Analysis with RAG
Analyzes security events using retrieval-augmented generation for intelligent remediation
"""

import openai
import boto3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import requests
from pinecone import Pinecone, ServerlessSpec
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import Pinecone as LangchainPinecone
from langchain.text_splitter import RecursiveCharacterTextSplitter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityAgent:
    """
    GPT-4 powered security agent that uses RAG (Retrieval-Augmented Generation)
    to analyze vulnerabilities against historical incident database and generate
    intelligent remediation playbooks.
    """

    def __init__(
        self,
        openai_api_key: str,
        pinecone_api_key: str,
        pinecone_environment: str,
        splunk_url: str,
        splunk_token: str,
        aws_region: str = 'us-east-1'
    ):
        """
        Initialize Security Agent with AI and observability integrations

        Args:
            openai_api_key: OpenAI API key for GPT-4
            pinecone_api_key: Pinecone API key for vector database
            pinecone_environment: Pinecone environment
            splunk_url: Splunk instance URL
            splunk_token: Splunk authentication token
            aws_region: AWS region
        """
        # OpenAI GPT-4 setup
        openai.api_key = openai_api_key
        self.client = openai.OpenAI(api_key=openai_api_key)

        # Pinecone vector database setup
        self.pc = Pinecone(api_key=pinecone_api_key)
        self.embeddings = OpenAIEmbeddings(openai_api_key=openai_api_key)

        # Initialize or connect to Pinecone index
        self.index_name = "security-incidents"
        if self.index_name not in self.pc.list_indexes().names():
            self.pc.create_index(
                name=self.index_name,
                dimension=1536,  # OpenAI embedding dimension
                metric='cosine',
                spec=ServerlessSpec(cloud='aws', region='us-east-1')
            )

        self.vector_store = LangchainPinecone.from_existing_index(
            self.index_name,
            self.embeddings
        )

        # Splunk setup
        self.splunk_url = splunk_url
        self.splunk_headers = {
            'Authorization': f'Bearer {splunk_token}',
            'Content-Type': 'application/json'
        }

        # AWS setup
        self.ssm = boto3.client('ssm', region_name=aws_region)
        self.sns = boto3.client('sns', region_name=aws_region)
        self.securityhub = boto3.client('securityhub', region_name=aws_region)

        logger.info("Security Agent initialized with GPT-4 and RAG capabilities")

    def fetch_splunk_events(self, query: str, timeframe_hours: int = 24) -> List[Dict]:
        """
        Fetch security events from Splunk

        Args:
            query: Splunk search query
            timeframe_hours: Hours of historical data to fetch

        Returns:
            List of security events
        """
        search_query = {
            "search": f"search {query}",
            "earliest_time": f"-{timeframe_hours}h",
            "latest_time": "now",
            "output_mode": "json"
        }

        logger.info(f"Querying Splunk: {query}")

        try:
            response = requests.post(
                f"{self.splunk_url}/services/search/jobs/export",
                headers=self.splunk_headers,
                data=search_query,
                verify=False
            )

            events = []
            for line in response.text.strip().split('\n'):
                if line:
                    events.append(json.loads(line))

            logger.info(f"Fetched {len(events)} events from Splunk")
            return events

        except Exception as e:
            logger.error(f"Error fetching Splunk events: {e}")
            return []

    def analyze_vulnerability(self, cve_id: str, context: Dict) -> Dict:
        """
        Analyze vulnerability using GPT-4 with RAG for context-aware remediation

        Args:
            cve_id: CVE identifier
            context: Additional context (affected systems, services, etc.)

        Returns:
            Analysis with remediation recommendations
        """
        logger.info(f"Analyzing vulnerability: {cve_id}")

        # Retrieve similar past incidents from vector database
        similar_incidents = self.vector_store.similarity_search(
            f"CVE: {cve_id} Context: {json.dumps(context)}",
            k=5
        )

        # Build context from retrieved incidents
        historical_context = "\n\n".join([
            f"Past Incident {i+1}:\n{doc.page_content}"
            for i, doc in enumerate(similar_incidents)
        ])

        # GPT-4 analysis with RAG
        prompt = f"""
You are an expert security analyst reviewing a critical vulnerability.

VULNERABILITY DETAILS:
CVE ID: {cve_id}
Affected Systems: {context.get('affected_systems', 'Unknown')}
Services Impacted: {context.get('services', 'Unknown')}
Environment: {context.get('environment', 'production')}
Severity: {context.get('severity', 'Unknown')}

SIMILAR HISTORICAL INCIDENTS:
{historical_context}

Based on the CVE details and similar past incidents, provide:

1. RISK ASSESSMENT (score 1-10 and rationale)
2. IMMEDIATE ACTIONS (what to do in next 30 minutes)
3. REMEDIATION PLAN (step-by-step mitigation)
4. ANSIBLE PLAYBOOK (automated remediation code)
5. VALIDATION STEPS (how to verify fix)
6. LONG-TERM PREVENTION (architectural improvements)

Format your response as JSON with these exact keys:
- risk_score
- risk_rationale
- immediate_actions (array)
- remediation_plan (array)
- ansible_playbook (string)
- validation_steps (array)
- prevention_measures (array)
- confidence (float 0-1)
"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4-turbo",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior security engineer specializing in vulnerability management and incident response. Provide detailed, actionable remediation guidance."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.2,
                response_format={"type": "json_object"}
            )

            analysis = json.loads(response.choices[0].message.content)
            analysis['cve_id'] = cve_id
            analysis['analyzed_at'] = datetime.now().isoformat()
            analysis['similar_incidents_count'] = len(similar_incidents)

            logger.info(f"GPT-4 analysis complete. Risk score: {analysis.get('risk_score', 'N/A')}")

            # Store this analysis in vector database for future reference
            self._store_incident(cve_id, context, analysis)

            return analysis

        except Exception as e:
            logger.error(f"Error in GPT-4 analysis: {e}")
            return {"error": str(e), "cve_id": cve_id}

    def _store_incident(self, cve_id: str, context: Dict, analysis: Dict):
        """
        Store incident analysis in vector database for future RAG retrieval

        Args:
            cve_id: CVE identifier
            context: Incident context
            analysis: GPT-4 analysis results
        """
        incident_text = f"""
CVE: {cve_id}
Affected Systems: {context.get('affected_systems', 'Unknown')}
Services: {context.get('services', 'Unknown')}
Risk Score: {analysis.get('risk_score', 'N/A')}
Remediation: {' '.join(analysis.get('remediation_plan', []))}
Outcome: Successfully mitigated
        """

        self.vector_store.add_texts(
            texts=[incident_text],
            metadatas=[{
                'cve_id': cve_id,
                'timestamp': datetime.now().isoformat(),
                'risk_score': analysis.get('risk_score', 0)
            }]
        )

        logger.info(f"Stored incident {cve_id} in vector database")

    def auto_remediate(self, ansible_playbook: str, target_hosts: List[str]) -> Dict:
        """
        Execute automated remediation using Ansible via AWS Systems Manager

        Args:
            ansible_playbook: Ansible playbook YAML content
            target_hosts: List of EC2 instance IDs to target

        Returns:
            Execution results
        """
        logger.info(f"Executing auto-remediation on {len(target_hosts)} hosts")

        try:
            # Send command via SSM
            response = self.ssm.send_command(
                InstanceIds=target_hosts,
                DocumentName="AWS-RunAnsiblePlaybook",
                Parameters={
                    'playbookContent': [ansible_playbook],
                    'checkMode': ['False'],
                    'verbose': ['-v']
                },
                TimeoutSeconds=600
            )

            command_id = response['Command']['CommandId']

            logger.info(f"SSM Command sent: {command_id}")

            return {
                'command_id': command_id,
                'status': 'initiated',
                'target_count': len(target_hosts),
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Error executing remediation: {e}")
            return {'error': str(e)}

    def analyze_security_logs(self, timeframe_hours: int = 1) -> Dict:
        """
        Analyze recent security logs for threats using GPT-4

        Args:
            timeframe_hours: Hours of logs to analyze

        Returns:
            Security analysis with threat assessment
        """
        # Fetch authentication failures
        auth_failures = self.fetch_splunk_events(
            'index=security sourcetype=auth action=failure',
            timeframe_hours
        )

        # Fetch suspicious network activity
        network_events = self.fetch_splunk_events(
            'index=network (dest_port=22 OR dest_port=3389) action=blocked',
            timeframe_hours
        )

        # Fetch AWS CloudTrail unauthorized attempts
        cloudtrail_events = self.fetch_splunk_events(
            'index=aws sourcetype=aws:cloudtrail errorCode=*Unauthorized*',
            timeframe_hours
        )

        # Combine events
        all_events = {
            'auth_failures': auth_failures[:50],  # Limit to 50 most recent
            'network_blocks': network_events[:50],
            'cloudtrail_unauthorized': cloudtrail_events[:50]
        }

        # GPT-4 analysis
        prompt = f"""
Analyze these security events from the past {timeframe_hours} hour(s):

AUTHENTICATION FAILURES: {len(auth_failures)}
Sample events: {json.dumps(auth_failures[:5], indent=2)}

BLOCKED NETWORK ACTIVITY: {len(network_events)}
Sample events: {json.dumps(network_events[:5], indent=2)}

AWS UNAUTHORIZED ATTEMPTS: {len(cloudtrail_events)}
Sample events: {json.dumps(cloudtrail_events[:5], indent=2)}

Provide a security analysis in JSON format:
- threat_level (low/medium/high/critical)
- summary (brief overview)
- key_findings (array of important observations)
- recommended_actions (array of immediate actions)
- potential_attackers (array with IP addresses, patterns)
- indicators_of_compromise (array)
"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4-turbo",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity threat analyst. Analyze security events and identify patterns, threats, and attack indicators."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,
                response_format={"type": "json_object"}
            )

            analysis = json.loads(response.choices[0].message.content)
            analysis['event_counts'] = {
                'auth_failures': len(auth_failures),
                'network_blocks': len(network_events),
                'cloudtrail_unauthorized': len(cloudtrail_events)
            }
            analysis['analyzed_at'] = datetime.now().isoformat()

            logger.info(f"Security log analysis complete. Threat level: {analysis.get('threat_level')}")

            # Send alert if high/critical
            if analysis.get('threat_level') in ['high', 'critical']:
                self._send_security_alert(analysis)

            return analysis

        except Exception as e:
            logger.error(f"Error analyzing security logs: {e}")
            return {"error": str(e)}

    def _send_security_alert(self, analysis: Dict):
        """
        Send security alert via SNS

        Args:
            analysis: Security analysis results
        """
        try:
            message = f"""
SECURITY ALERT - {analysis.get('threat_level', 'UNKNOWN').upper()}

{analysis.get('summary', 'Security threat detected')}

KEY FINDINGS:
{chr(10).join('- ' + f for f in analysis.get('key_findings', []))}

RECOMMENDED ACTIONS:
{chr(10).join('- ' + a for a in analysis.get('recommended_actions', []))}

Analyzed at: {analysis.get('analyzed_at')}
            """

            self.sns.publish(
                TopicArn='arn:aws:sns:us-east-1:123456789012:security-alerts',
                Subject=f"SECURITY ALERT - {analysis.get('threat_level', 'UNKNOWN').upper()}",
                Message=message
            )

            logger.info("Security alert sent via SNS")

        except Exception as e:
            logger.error(f"Error sending security alert: {e}")

    def scan_infrastructure(self) -> Dict:
        """
        Scan AWS infrastructure for security vulnerabilities using Security Hub

        Returns:
            Security findings summary
        """
        try:
            # Get findings from AWS Security Hub
            response = self.securityhub.get_findings(
                Filters={
                    'SeverityLabel': [
                        {'Value': 'CRITICAL', 'Comparison': 'EQUALS'},
                        {'Value': 'HIGH', 'Comparison': 'EQUALS'}
                    ],
                    'RecordState': [
                        {'Value': 'ACTIVE', 'Comparison': 'EQUALS'}
                    ]
                },
                MaxResults=100
            )

            findings = response.get('Findings', [])

            # Categorize findings
            findings_by_type = {}
            for finding in findings:
                finding_type = finding.get('Types', ['Unknown'])[0]
                if finding_type not in findings_by_type:
                    findings_by_type[finding_type] = []
                findings_by_type[finding_type].append(finding)

            summary = {
                'total_findings': len(findings),
                'critical': len([f for f in findings if f.get('Severity', {}).get('Label') == 'CRITICAL']),
                'high': len([f for f in findings if f.get('Severity', {}).get('Label') == 'HIGH']),
                'findings_by_type': {k: len(v) for k, v in findings_by_type.items()},
                'top_resources': self._get_top_vulnerable_resources(findings),
                'scanned_at': datetime.now().isoformat()
            }

            logger.info(f"Infrastructure scan complete. Total findings: {summary['total_findings']}")

            return summary

        except Exception as e:
            logger.error(f"Error scanning infrastructure: {e}")
            return {"error": str(e)}

    def _get_top_vulnerable_resources(self, findings: List[Dict], limit: int = 10) -> List[Dict]:
        """
        Get resources with most security findings

        Args:
            findings: Security findings
            limit: Number of top resources to return

        Returns:
            List of vulnerable resources
        """
        resource_counts = {}

        for finding in findings:
            for resource in finding.get('Resources', []):
                resource_id = resource.get('Id', 'Unknown')
                if resource_id not in resource_counts:
                    resource_counts[resource_id] = {
                        'id': resource_id,
                        'type': resource.get('Type', 'Unknown'),
                        'findings': 0
                    }
                resource_counts[resource_id]['findings'] += 1

        # Sort by finding count
        sorted_resources = sorted(
            resource_counts.values(),
            key=lambda x: x['findings'],
            reverse=True
        )

        return sorted_resources[:limit]


if __name__ == "__main__":
    # Example usage
    import os

    agent = SecurityAgent(
        openai_api_key=os.environ.get('OPENAI_API_KEY'),
        pinecone_api_key=os.environ.get('PINECONE_API_KEY'),
        pinecone_environment='us-east-1',
        splunk_url=os.environ.get('SPLUNK_URL'),
        splunk_token=os.environ.get('SPLUNK_TOKEN')
    )

    # Analyze a vulnerability
    analysis = agent.analyze_vulnerability(
        cve_id='CVE-2024-1234',
        context={
            'affected_systems': ['web-server-01', 'web-server-02'],
            'services': ['nginx', 'php-fpm'],
            'environment': 'production',
            'severity': 'high'
        }
    )

    print(json.dumps(analysis, indent=2))

    # Auto-remediate if confidence is high
    if analysis.get('confidence', 0) > 0.90:
        agent.auto_remediate(
            ansible_playbook=analysis['ansible_playbook'],
            target_hosts=['i-1234567890abcdef0', 'i-0987654321fedcba0']
        )
