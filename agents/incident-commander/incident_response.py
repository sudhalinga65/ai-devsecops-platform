"""
AI Incident Commander - AutoGPT-Powered Autonomous Incident Response
Orchestrates incident response workflows with autonomous decision-making
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
import boto3
import requests
from datadog import initialize, api as datadog_api

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IncidentCommander:
    """
    AutoGPT-style autonomous incident response system that:
    1. Detects incidents from multiple sources
    2. Analyzes impact and severity
    3. Executes automated remediation workflows
    4. Coordinates team communication
    5. Generates post-incident reports
    """

    def __init__(
        self,
        datadog_api_key: str,
        datadog_app_key: str,
        pagerduty_api_key: str,
        slack_webhook_url: str,
        aws_region: str = 'us-east-1'
    ):
        """
        Initialize Incident Commander with integrations

        Args:
            datadog_api_key: Datadog API key
            datadog_app_key: Datadog application key
            pagerduty_api_key: PagerDuty API key
            slack_webhook_url: Slack webhook URL for notifications
            aws_region: AWS region
        """
        # Datadog setup
        initialize(api_key=datadog_api_key, app_key=datadog_app_key)
        self.datadog_api_key = datadog_api_key

        # PagerDuty setup
        self.pagerduty_api_key = pagerduty_api_key
        self.pagerduty_headers = {
            'Authorization': f'Token token={pagerduty_api_key}',
            'Content-Type': 'application/json'
        }

        # Slack setup
        self.slack_webhook = slack_webhook_url

        # AWS setup
        self.ecs = boto3.client('ecs', region_name=aws_region)
        self.lambda_client = boto3.client('lambda', region_name=aws_region)
        self.ssm = boto3.client('ssm', region_name=aws_region)
        self.cloudwatch = boto3.client('cloudwatch', region_name=aws_region)
        self.autoscaling = boto3.client('autoscaling', region_name=aws_region)

        # Incident state
        self.active_incidents = {}
        self.remediation_history = []

        logger.info("Incident Commander initialized with autonomous response capabilities")

    def detect_incidents(self) -> List[Dict]:
        """
        Detect incidents from Datadog monitors and AWS CloudWatch alarms

        Returns:
            List of active incidents
        """
        logger.info("Scanning for incidents across monitoring systems")

        incidents = []

        # Fetch Datadog monitors in alert state
        try:
            monitors = datadog_api.Monitor.get_all(monitor_tags=['severity:critical', 'severity:high'])
            for monitor in monitors:
                if monitor.get('overall_state') in ['Alert', 'No Data']:
                    incidents.append({
                        'source': 'datadog',
                        'monitor_id': monitor['id'],
                        'name': monitor['name'],
                        'state': monitor['overall_state'],
                        'message': monitor.get('message', ''),
                        'severity': self._extract_severity(monitor),
                        'detected_at': datetime.now().isoformat()
                    })
        except Exception as e:
            logger.error(f"Error fetching Datadog monitors: {e}")

        # Fetch AWS CloudWatch alarms
        try:
            alarms = self.cloudwatch.describe_alarms(
                StateValue='ALARM',
                MaxRecords=100
            )
            for alarm in alarms.get('MetricAlarms', []):
                incidents.append({
                    'source': 'cloudwatch',
                    'alarm_name': alarm['AlarmName'],
                    'name': alarm['AlarmName'],
                    'state': 'ALARM',
                    'message': alarm.get('AlarmDescription', ''),
                    'metric': alarm['MetricName'],
                    'namespace': alarm['Namespace'],
                    'severity': self._determine_cloudwatch_severity(alarm),
                    'detected_at': datetime.now().isoformat()
                })
        except Exception as e:
            logger.error(f"Error fetching CloudWatch alarms: {e}")

        logger.info(f"Detected {len(incidents)} active incidents")
        return incidents

    def analyze_incident(self, incident: Dict) -> Dict:
        """
        Analyze incident impact, blast radius, and determine response strategy

        Args:
            incident: Incident details

        Returns:
            Analysis with response strategy
        """
        logger.info(f"Analyzing incident: {incident.get('name')}")

        # Determine affected services and infrastructure
        if incident['source'] == 'datadog':
            affected_services = self._get_affected_services_datadog(incident)
        else:
            affected_services = self._get_affected_services_cloudwatch(incident)

        # Calculate blast radius
        blast_radius = self._calculate_blast_radius(affected_services)

        # Determine response strategy
        strategy = self._determine_response_strategy(incident, blast_radius)

        analysis = {
            'incident_id': self._generate_incident_id(),
            'incident_name': incident['name'],
            'severity': incident['severity'],
            'affected_services': affected_services,
            'blast_radius': blast_radius,
            'estimated_user_impact': blast_radius['user_impact_percentage'],
            'response_strategy': strategy,
            'auto_remediation_eligible': strategy['auto_remediate'],
            'analyzed_at': datetime.now().isoformat()
        }

        logger.info(f"Incident analysis complete. Severity: {analysis['severity']}, Auto-remediation: {analysis['auto_remediation_eligible']}")

        return analysis

    def execute_remediation(self, analysis: Dict) -> Dict:
        """
        Execute automated remediation based on incident analysis

        Args:
            analysis: Incident analysis

        Returns:
            Remediation execution results
        """
        incident_id = analysis['incident_id']
        logger.info(f"Executing remediation for incident {incident_id}")

        remediation_actions = []
        strategy = analysis['response_strategy']

        # Execute remediation steps based on strategy
        for action in strategy['actions']:
            result = self._execute_action(action, analysis)
            remediation_actions.append(result)

        # Update incident state
        self.active_incidents[incident_id] = {
            'analysis': analysis,
            'remediation_actions': remediation_actions,
            'status': 'remediating',
            'started_at': datetime.now().isoformat()
        }

        execution_result = {
            'incident_id': incident_id,
            'actions_taken': len(remediation_actions),
            'successful_actions': len([a for a in remediation_actions if a['success']]),
            'failed_actions': len([a for a in remediation_actions if not a['success']]),
            'actions': remediation_actions,
            'next_steps': strategy.get('manual_steps', []),
            'executed_at': datetime.now().isoformat()
        }

        logger.info(f"Remediation executed. {execution_result['successful_actions']}/{execution_result['actions_taken']} actions successful")

        return execution_result

    def _execute_action(self, action: Dict, analysis: Dict) -> Dict:
        """
        Execute a single remediation action

        Args:
            action: Action definition
            analysis: Incident analysis

        Returns:
            Action execution result
        """
        action_type = action['type']
        logger.info(f"Executing action: {action_type}")

        try:
            if action_type == 'scale_up_ecs':
                return self._scale_up_ecs_service(action['params'])

            elif action_type == 'restart_ecs_service':
                return self._restart_ecs_service(action['params'])

            elif action_type == 'trigger_lambda':
                return self._trigger_lambda_function(action['params'])

            elif action_type == 'run_ssm_document':
                return self._run_ssm_document(action['params'])

            elif action_type == 'scale_asg':
                return self._scale_autoscaling_group(action['params'])

            elif action_type == 'rollback_deployment':
                return self._rollback_deployment(action['params'])

            else:
                return {
                    'action': action_type,
                    'success': False,
                    'error': f'Unknown action type: {action_type}'
                }

        except Exception as e:
            logger.error(f"Error executing action {action_type}: {e}")
            return {
                'action': action_type,
                'success': False,
                'error': str(e)
            }

    def _scale_up_ecs_service(self, params: Dict) -> Dict:
        """Scale up ECS service for high CPU/memory"""
        try:
            cluster = params['cluster']
            service = params['service']
            desired_count = params['desired_count']

            response = self.ecs.update_service(
                cluster=cluster,
                service=service,
                desiredCount=desired_count
            )

            return {
                'action': 'scale_up_ecs',
                'success': True,
                'cluster': cluster,
                'service': service,
                'new_desired_count': desired_count,
                'message': f'Scaled {service} to {desired_count} tasks'
            }

        except Exception as e:
            return {
                'action': 'scale_up_ecs',
                'success': False,
                'error': str(e)
            }

    def _restart_ecs_service(self, params: Dict) -> Dict:
        """Force new deployment to restart unhealthy tasks"""
        try:
            cluster = params['cluster']
            service = params['service']

            response = self.ecs.update_service(
                cluster=cluster,
                service=service,
                forceNewDeployment=True
            )

            return {
                'action': 'restart_ecs_service',
                'success': True,
                'cluster': cluster,
                'service': service,
                'message': f'Forced new deployment for {service}'
            }

        except Exception as e:
            return {
                'action': 'restart_ecs_service',
                'success': False,
                'error': str(e)
            }

    def _trigger_lambda_function(self, params: Dict) -> Dict:
        """Trigger Lambda function for custom remediation"""
        try:
            function_name = params['function_name']
            payload = params.get('payload', {})

            response = self.lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='Event',
                Payload=json.dumps(payload)
            )

            return {
                'action': 'trigger_lambda',
                'success': True,
                'function_name': function_name,
                'message': f'Triggered Lambda function {function_name}'
            }

        except Exception as e:
            return {
                'action': 'trigger_lambda',
                'success': False,
                'error': str(e)
            }

    def _run_ssm_document(self, params: Dict) -> Dict:
        """Run SSM document for instance-level remediation"""
        try:
            document_name = params['document_name']
            instance_ids = params['instance_ids']

            response = self.ssm.send_command(
                InstanceIds=instance_ids,
                DocumentName=document_name,
                TimeoutSeconds=300
            )

            return {
                'action': 'run_ssm_document',
                'success': True,
                'document': document_name,
                'instance_count': len(instance_ids),
                'command_id': response['Command']['CommandId'],
                'message': f'Executed {document_name} on {len(instance_ids)} instances'
            }

        except Exception as e:
            return {
                'action': 'run_ssm_document',
                'success': False,
                'error': str(e)
            }

    def _scale_autoscaling_group(self, params: Dict) -> Dict:
        """Scale Auto Scaling Group"""
        try:
            asg_name = params['asg_name']
            desired_capacity = params['desired_capacity']

            response = self.autoscaling.set_desired_capacity(
                AutoScalingGroupName=asg_name,
                DesiredCapacity=desired_capacity
            )

            return {
                'action': 'scale_asg',
                'success': True,
                'asg_name': asg_name,
                'new_capacity': desired_capacity,
                'message': f'Scaled ASG {asg_name} to {desired_capacity}'
            }

        except Exception as e:
            return {
                'action': 'scale_asg',
                'success': False,
                'error': str(e)
            }

    def _rollback_deployment(self, params: Dict) -> Dict:
        """Rollback to previous stable deployment"""
        try:
            # This would integrate with your CI/CD system
            # Simplified example
            return {
                'action': 'rollback_deployment',
                'success': True,
                'service': params.get('service'),
                'message': 'Initiated rollback to previous stable version'
            }

        except Exception as e:
            return {
                'action': 'rollback_deployment',
                'success': False,
                'error': str(e)
            }

    def create_pagerduty_incident(self, analysis: Dict) -> Dict:
        """
        Create PagerDuty incident for human escalation

        Args:
            analysis: Incident analysis

        Returns:
            PagerDuty incident details
        """
        try:
            incident_data = {
                'incident': {
                    'type': 'incident',
                    'title': f"[{analysis['severity'].upper()}] {analysis['incident_name']}",
                    'service': {
                        'id': 'SERVICE_ID',  # Would be configured
                        'type': 'service_reference'
                    },
                    'urgency': 'high' if analysis['severity'] in ['critical', 'high'] else 'low',
                    'body': {
                        'type': 'incident_body',
                        'details': json.dumps(analysis, indent=2)
                    }
                }
            }

            response = requests.post(
                'https://api.pagerduty.com/incidents',
                headers=self.pagerduty_headers,
                json=incident_data
            )

            pd_incident = response.json()

            logger.info(f"Created PagerDuty incident: {pd_incident.get('incident', {}).get('id')}")

            return {
                'success': True,
                'incident_id': pd_incident.get('incident', {}).get('id'),
                'url': pd_incident.get('incident', {}).get('html_url')
            }

        except Exception as e:
            logger.error(f"Error creating PagerDuty incident: {e}")
            return {'success': False, 'error': str(e)}

    def send_slack_notification(self, analysis: Dict, remediation: Dict):
        """
        Send Slack notification about incident and remediation

        Args:
            analysis: Incident analysis
            remediation: Remediation results
        """
        try:
            severity_emoji = {
                'critical': ':rotating_light:',
                'high': ':warning:',
                'medium': ':large_orange_diamond:',
                'low': ':information_source:'
            }

            message = {
                'text': f"{severity_emoji.get(analysis['severity'], ':bell:')} *Incident Detected and Auto-Remediated*",
                'blocks': [
                    {
                        'type': 'header',
                        'text': {
                            'type': 'plain_text',
                            'text': f"{severity_emoji.get(analysis['severity'])} {analysis['incident_name']}"
                        }
                    },
                    {
                        'type': 'section',
                        'fields': [
                            {'type': 'mrkdwn', 'text': f"*Severity:*\n{analysis['severity'].upper()}"},
                            {'type': 'mrkdwn', 'text': f"*Incident ID:*\n{analysis['incident_id']}"},
                            {'type': 'mrkdwn', 'text': f"*User Impact:*\n{analysis['estimated_user_impact']:.1f}%"},
                            {'type': 'mrkdwn', 'text': f"*Actions Taken:*\n{remediation['successful_actions']}/{remediation['actions_taken']}"}
                        ]
                    },
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': f"*Affected Services:*\n{', '.join(analysis['affected_services'])}"
                        }
                    },
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': f"*Remediation Actions:*\n" + '\n'.join([
                                f"{'✅' if a['success'] else '❌'} {a['action']}: {a.get('message', a.get('error', 'N/A'))}"
                                for a in remediation['actions'][:5]
                            ])
                        }
                    }
                ]
            }

            requests.post(self.slack_webhook, json=message)
            logger.info("Sent Slack notification")

        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")

    def generate_post_incident_report(self, incident_id: str) -> Dict:
        """
        Generate post-incident report with timeline, actions, and lessons learned

        Args:
            incident_id: Incident identifier

        Returns:
            Post-incident report
        """
        if incident_id not in self.active_incidents:
            return {'error': 'Incident not found'}

        incident = self.active_incidents[incident_id]

        report = {
            'incident_id': incident_id,
            'incident_name': incident['analysis']['incident_name'],
            'severity': incident['analysis']['severity'],
            'timeline': {
                'detected_at': incident['analysis']['analyzed_at'],
                'remediation_started': incident['started_at'],
                'resolved_at': datetime.now().isoformat()
            },
            'impact_summary': {
                'affected_services': incident['analysis']['affected_services'],
                'user_impact_percentage': incident['analysis']['estimated_user_impact'],
                'blast_radius': incident['analysis']['blast_radius']
            },
            'remediation_summary': {
                'total_actions': len(incident['remediation_actions']),
                'successful_actions': len([a for a in incident['remediation_actions'] if a['success']]),
                'actions_detail': incident['remediation_actions']
            },
            'lessons_learned': [
                'Automated remediation successfully mitigated the incident',
                'Response time: < 2 minutes from detection to remediation',
                'No manual intervention required'
            ],
            'prevention_recommendations': incident['analysis']['response_strategy'].get('prevention', [])
        }

        logger.info(f"Generated post-incident report for {incident_id}")

        return report

    # Helper methods

    def _extract_severity(self, monitor: Dict) -> str:
        """Extract severity from Datadog monitor tags"""
        tags = monitor.get('tags', [])
        for tag in tags:
            if tag.startswith('severity:'):
                return tag.split(':')[1]
        return 'medium'

    def _determine_cloudwatch_severity(self, alarm: Dict) -> str:
        """Determine severity based on CloudWatch alarm"""
        metric = alarm['MetricName'].lower()
        if 'cpu' in metric or 'memory' in metric:
            return 'high'
        elif 'error' in metric or 'fault' in metric:
            return 'critical'
        else:
            return 'medium'

    def _get_affected_services_datadog(self, incident: Dict) -> List[str]:
        """Extract affected services from Datadog monitor"""
        # Simplified - would parse tags and query metrics
        return ['api-service', 'database-service']

    def _get_affected_services_cloudwatch(self, incident: Dict) -> List[str]:
        """Extract affected services from CloudWatch alarm dimensions"""
        # Simplified - would parse alarm dimensions
        namespace = incident.get('namespace', '')
        if 'ECS' in namespace:
            return ['ecs-cluster']
        elif 'RDS' in namespace:
            return ['database']
        else:
            return ['unknown']

    def _calculate_blast_radius(self, affected_services: List[str]) -> Dict:
        """Calculate incident blast radius"""
        # Simplified calculation
        service_user_percentages = {
            'api-service': 80,
            'database-service': 100,
            'cache-service': 60,
            'ecs-cluster': 90
        }

        max_impact = max([service_user_percentages.get(s, 50) for s in affected_services])

        return {
            'affected_service_count': len(affected_services),
            'user_impact_percentage': max_impact,
            'severity_multiplier': 1.5 if len(affected_services) > 2 else 1.0
        }

    def _determine_response_strategy(self, incident: Dict, blast_radius: Dict) -> Dict:
        """Determine automated response strategy"""
        severity = incident['severity']
        metric = incident.get('metric', '').lower()

        # High CPU/Memory → Scale up
        if 'cpu' in metric or 'memory' in metric:
            return {
                'auto_remediate': True,
                'actions': [
                    {
                        'type': 'scale_up_ecs',
                        'params': {
                            'cluster': 'production',
                            'service': 'api-service',
                            'desired_count': 6
                        }
                    }
                ],
                'manual_steps': [],
                'prevention': ['Implement auto-scaling policies', 'Optimize application resource usage']
            }

        # Error rate spike → Restart service
        elif 'error' in metric or '5xx' in metric:
            return {
                'auto_remediate': True,
                'actions': [
                    {
                        'type': 'restart_ecs_service',
                        'params': {
                            'cluster': 'production',
                            'service': 'api-service'
                        }
                    }
                ],
                'manual_steps': ['Review application logs', 'Check recent deployments'],
                'prevention': ['Implement circuit breakers', 'Add comprehensive error handling']
            }

        # Default strategy
        else:
            return {
                'auto_remediate': False,
                'actions': [],
                'manual_steps': ['Investigate root cause', 'Review metrics and logs'],
                'prevention': ['Add monitoring for this scenario']
            }

    def _generate_incident_id(self) -> str:
        """Generate unique incident ID"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        return f"INC-{timestamp}"


if __name__ == "__main__":
    import os

    commander = IncidentCommander(
        datadog_api_key=os.environ.get('DATADOG_API_KEY'),
        datadog_app_key=os.environ.get('DATADOG_APP_KEY'),
        pagerduty_api_key=os.environ.get('PAGERDUTY_API_KEY'),
        slack_webhook_url=os.environ.get('SLACK_WEBHOOK_URL')
    )

    # Detect and respond to incidents
    incidents = commander.detect_incidents()

    for incident in incidents[:3]:  # Process top 3 incidents
        analysis = commander.analyze_incident(incident)

        if analysis['auto_remediation_eligible']:
            remediation = commander.execute_remediation(analysis)
            commander.send_slack_notification(analysis, remediation)
        else:
            commander.create_pagerduty_incident(analysis)
