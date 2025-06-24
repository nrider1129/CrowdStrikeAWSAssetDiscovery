#!/usr/bin/env python3

import boto3
import logging
import datetime
import concurrent.futures
import argparse
from botocore.exceptions import ClientError
from typing import Dict, List, Any
import threading
from queue import Queue
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from collections import defaultdict

class FalconSecurityMapping:
    """Class to handle Falcon security service mappings and recommendations"""
    
    def __init__(self):
        self.service_mappings = {
            'EC2': {
                'primary_service': 'Falcon Cloud Workload Protection',
                'features': [
                    'Real-time host protection',
                    'Vulnerability management',
                    'File integrity monitoring',
                    'Host firewall management'
                ],
                'additional_services': [
                    'Falcon Spotlight',
                    'Falcon Device Control'
                ],
                'compliance_frameworks': [
                    'PCI DSS',
                    'HIPAA',
                    'SOC 2'
                ],
                'risk_level': 'High',
                'implementation_priority': 1
            },
            'S3': {
                'primary_service': 'Falcon Cloud Security CSPM',
                'features': [
                    'Storage security assessment',
                    'Data protection policies',
                    'Bucket misconfiguration detection',
                    'Public access monitoring'
                ],
                'additional_services': [
                    'Falcon Data Protection',
                    'Falcon Intelligence'
                ],
                'compliance_frameworks': [
                    'GDPR',
                    'CCPA',
                    'PCI DSS'
                ],
                'risk_level': 'High',
                'implementation_priority': 1
            },
            'Lambda': {
                'primary_service': 'Falcon Container Security',
                'features': [
                    'Serverless function protection',
                    'Runtime security',
                    'Third-party dependency scanning',
                    'Function configuration assessment'
                ],
                'additional_services': [
                    'Falcon Intelligence for Cloud',
                    'Falcon CNAP'
                ],
                'compliance_frameworks': [
                    'SOC 2',
                    'ISO 27001'
                ],
                'risk_level': 'Medium',
                'implementation_priority': 2
            },
            'RDS': {
                'primary_service': 'Falcon Cloud Security CSPM',
                'features': [
                    'Database security assessment',
                    'Configuration monitoring',
                    'Access control validation',
                    'Encryption verification'
                ],
                'additional_services': [
                    'Falcon Data Protection',
                    'Falcon Intelligence'
                ],
                'compliance_frameworks': [
                    'GDPR',
                    'HIPAA',
                    'PCI DSS'
                ],
                'risk_level': 'High',
                'implementation_priority': 1
            },
            'ECS': {
                'primary_service': 'Falcon Container Security',
                'features': [
                    'Container runtime protection',
                    'Image scanning',
                    'Container drift prevention',
                    'Container security monitoring'
                ],
                'additional_services': [
                    'Falcon Cloud Workload Protection',
                    'Falcon Intelligence'
                ],
                'compliance_frameworks': [
                    'PCI DSS',
                    'HIPAA',
                    'ISO 27001'
                ],
                'risk_level': 'High',
                'implementation_priority': 1
            }
        }
class AWSAssetDiscovery:
    def __init__(self, 
                 org_wide: bool = False, 
                 target_account: str = None,
                 master_role_name: str = "OrganizationAccountAccessRole",
                 profile_name: str = None):
        self.org_wide = org_wide
        self.target_account = target_account
        self.master_role_name = master_role_name
        self.session = boto3.Session(profile_name=profile_name)
        self.account_credentials_cache = {}
        self.credentials_lock = threading.Lock()
        self.results = []
        self.results_lock = threading.Lock()
        self.console = Console()
        self.setup_logging()
        self.falcon_mapping = FalconSecurityMapping()
        self.security_findings = defaultdict(list)

    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            filename='discovery_errors.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def get_regions(self, session: boto3.Session) -> List[str]:
        """Get list of AWS regions"""
        try:
            ec2_client = session.client('ec2')
            regions = [region['RegionName'] for region in 
                      ec2_client.describe_regions()['Regions']]
            return regions
        except ClientError as e:
            self.logger.error(f"Error getting regions: {str(e)}")
            return ['us-east-1']

    def discover_resources(self, session: boto3.Session, region: str, service: str) -> List[Dict[str, Any]]:
        """Discover resources for a specific service in a region"""
        resources = []
        try:
            if service == 'EC2':
                client = session.client('ec2', region_name=region)
                try:
                    paginator = client.get_paginator('describe_instances')
                    for page in paginator.paginate():
                        for reservation in page['Reservations']:
                            for instance in reservation['Instances']:
                                try:
                                    name = next((tag['Value'] for tag in instance.get('Tags', []) 
                                              if tag['Key'] == 'Name'), 'NoName')
                                    state = instance.get('State', {}).get('Name', 'unknown')
                                    
                                    resources.append({
                                        'ServiceType': 'EC2',
                                        'ResourceId': instance['InstanceId'],
                                        'ResourceName': name,
                                        'Status': state,
                                        'Region': region
                                    })
                                except Exception as e:
                                    self.logger.warning(f"Error processing EC2 instance: {str(e)}")
                                    continue
                except ClientError as e:
                    self.logger.error(f"Error listing EC2 instances in {region}: {str(e)}")

            elif service == 'S3':
                client = session.client('s3')
                try:
                    response = client.list_buckets()
                    for bucket in response['Buckets']:
                        resources.append({
                            'ServiceType': 'S3',
                            'ResourceId': bucket['Name'],
                            'ResourceName': bucket['Name'],
                            'Status': 'Active',
                            'Region': 'global'
                        })
                except ClientError as e:
                    self.logger.error(f"Error listing S3 buckets: {str(e)}")

            elif service == 'Lambda':
                client = session.client('lambda', region_name=region)
                try:
                    paginator = client.get_paginator('list_functions')
                    for page in paginator.paginate():
                        for function in page['Functions']:
                            resources.append({
                                'ServiceType': 'Lambda',
                                'ResourceId': function['FunctionName'],
                                'ResourceName': function['FunctionName'],
                                'Status': function.get('State', 'Unknown'),
                                'Region': region
                            })
                except ClientError as e:
                    self.logger.error(f"Error listing Lambda functions in {region}: {str(e)}")

            elif service == 'RDS':
                client = session.client('rds', region_name=region)
                try:
                    paginator = client.get_paginator('describe_db_instances')
                    for page in paginator.paginate():
                        for instance in page['DBInstances']:
                            resources.append({
                                'ServiceType': 'RDS',
                                'ResourceId': instance['DBInstanceIdentifier'],
                                'ResourceName': instance['DBInstanceIdentifier'],
                                'Status': instance.get('DBInstanceStatus', 'Unknown'),
                                'Region': region
                            })
                except ClientError as e:
                    self.logger.error(f"Error listing RDS instances in {region}: {str(e)}")

            elif service == 'ECS':
                client = session.client('ecs', region_name=region)
                try:
                    paginator = client.get_paginator('list_clusters')
                    for page in paginator.paginate():
                        for cluster_arn in page['clusterArns']:
                            cluster_name = cluster_arn.split('/')[-1]
                            resources.append({
                                'ServiceType': 'ECS',
                                'ResourceId': cluster_arn,
                                'ResourceName': cluster_name,
                                'Status': 'Active',
                                'Region': region
                            })
                except ClientError as e:
                    self.logger.error(f"Error listing ECS clusters in {region}: {str(e)}")

        except Exception as e:
            self.logger.error(f"Error discovering {service} resources in {region}: {str(e)}")
        
        return resources
    def analyze_security_posture(self):
        """Analyze discovered resources and create security recommendations"""
        for resource in self.results:
            service_type = resource['ServiceType']
            if service_type in self.falcon_mapping.service_mappings:
                mapping = self.falcon_mapping.service_mappings[service_type]
                self.security_findings[service_type].append({
                    'resource_id': resource['ResourceId'],
                    'region': resource['Region'],
                    'mapping': mapping,
                    'status': resource.get('Status', 'unknown')
                })

    def display_security_recommendations(self):
        """Display summarized security recommendations based on discovered resources"""
        self.console.print("\n[bold blue]Falcon Security Recommendations[/bold blue]")

        # Create priority-based recommendations
        priority_findings = defaultdict(list)
        for service_type, findings in self.security_findings.items():
            mapping = self.falcon_mapping.service_mappings[service_type]
            priority = mapping['implementation_priority']
            priority_findings[priority].extend([(service_type, findings)])

        # Display recommendations by priority
        for priority in sorted(priority_findings.keys()):
            self.console.print(f"\n[bold yellow]Priority {priority} Recommendations:[/bold yellow]")
            
            for service_type, findings in priority_findings[priority]:
                mapping = self.falcon_mapping.service_mappings[service_type]
                
                # Create service summary table
                service_table = Table(show_header=True, header_style="bold magenta", 
                                   title=f"{service_type} Protection Summary")
                service_table.add_column("Category")
                service_table.add_column("Details")

                # Add service information
                service_table.add_row(
                    "Primary Falcon Service",
                    mapping['primary_service']
                )
                service_table.add_row(
                    "Resource Count",
                    str(len(findings))
                )
                service_table.add_row(
                    "Risk Level",
                    mapping['risk_level']
                )
                service_table.add_row(
                    "Key Features",
                    "\n".join(mapping['features'])
                )
                service_table.add_row(
                    "Additional Services",
                    "\n".join(mapping['additional_services'])
                )
                service_table.add_row(
                    "Compliance Frameworks",
                    "\n".join(mapping['compliance_frameworks'])
                )

                self.console.print(service_table)

                # Display resource count by region with EC2 state details
                if findings:
                    if service_type == 'EC2':
                        # Initialize region_counts with proper structure for EC2
                        region_counts = defaultdict(lambda: {
                            'total': 0,
                            'running': 0,
                            'stopped': 0,
                            'other': 0
                        })
                        
                        # Count EC2 instances by state and region
                        for finding in findings:
                            region = finding['region']
                            state = finding['status'].lower()
                            region_counts[region]['total'] += 1
                            
                            if state == 'running':
                                region_counts[region]['running'] += 1
                            elif state == 'stopped':
                                region_counts[region]['stopped'] += 1
                            else:
                                region_counts[region]['other'] += 1

                        # Create EC2-specific table
                        region_table = Table(show_header=True, header_style="bold cyan",
                                         title="EC2 Instance Distribution by Region")
                        region_table.add_column("Region")
                        region_table.add_column("Total")
                        region_table.add_column("Running", style="green")
                        region_table.add_column("Stopped", style="yellow")
                        region_table.add_column("Other", style="red")
                        
                        # Add rows for each region
                        for region, counts in sorted(region_counts.items()):
                            region_table.add_row(
                                region,
                                str(counts['total']),
                                str(counts['running']),
                                str(counts['stopped']),
                                str(counts['other'])
                            )

                        self.console.print(region_table)

                        # Add EC2 total summary
                        total_running = sum(counts['running'] for counts in region_counts.values())
                        total_stopped = sum(counts['stopped'] for counts in region_counts.values())
                        total_other = sum(counts['other'] for counts in region_counts.values())
                        total_instances = sum(counts['total'] for counts in region_counts.values())

                        ec2_summary = Table(title="EC2 Instance Summary", show_header=False)
                        ec2_summary.add_column("Category", style="bold")
                        ec2_summary.add_column("Count")
                        ec2_summary.add_row("Total Instances", str(total_instances))
                        ec2_summary.add_row("Running Instances", f"[green]{total_running}[/green]")
                        ec2_summary.add_row("Stopped Instances", f"[yellow]{total_stopped}[/yellow]")
                        ec2_summary.add_row("Other States", f"[red]{total_other}[/red]")

                        self.console.print(ec2_summary)
                    else:
                        # Handle non-EC2 services
                        region_counts = defaultdict(int)
                        for finding in findings:
                            region_counts[finding['region']] += 1
                        
                        region_table = Table(show_header=True, header_style="bold cyan",
                                         title=f"{service_type} Regional Distribution")
                        region_table.add_column("Region")
                        region_table.add_column("Resource Count")
                        
                        for region, count in sorted(region_counts.items()):
                            region_table.add_row(region, str(count))

                        self.console.print(region_table)
    def display_coverage_summary(self):
        """Display summary of Falcon coverage potential"""
        total_resources = len(self.results)
        covered_resources = sum(len(findings) for findings in self.security_findings.values())
        
        # Create summary table
        summary_table = Table(title="Falcon Coverage Summary", show_header=True)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Total Resources", str(total_resources))
        summary_table.add_row("Protectable Resources", str(covered_resources))
        if total_resources > 0:
            coverage_percentage = (covered_resources/total_resources*100)
            summary_table.add_row(
                "Coverage Potential",
                f"{coverage_percentage:.1f}%"
            )

        # Create service distribution table
        distribution_table = Table(title="Service Distribution", show_header=True)
        distribution_table.add_column("Service Type", style="blue")
        distribution_table.add_column("Resource Count", style="yellow")
        distribution_table.add_column("Percentage", style="green")

        service_counts = defaultdict(int)
        for resource in self.results:
            service_counts[resource['ServiceType']] += 1

        for service, count in sorted(service_counts.items()):
            percentage = (count / total_resources * 100) if total_resources > 0 else 0
            distribution_table.add_row(
                service,
                str(count),
                f"{percentage:.1f}%"
            )

        self.console.print("\n[bold green]Coverage Summary[/bold green]")
        self.console.print(summary_table)
        self.console.print("\n[bold green]Resource Distribution[/bold green]")
        self.console.print(distribution_table)

        # Display risk summary
        risk_table = Table(title="Risk Level Summary", show_header=True)
        risk_table.add_column("Risk Level", style="red")
        risk_table.add_column("Service Count", style="yellow")
        risk_table.add_column("Resource Count", style="green")

        risk_counts = defaultdict(lambda: {'services': set(), 'resources': 0})
        for service_type, findings in self.security_findings.items():
            risk_level = self.falcon_mapping.service_mappings[service_type]['risk_level']
            risk_counts[risk_level]['services'].add(service_type)
            risk_counts[risk_level]['resources'] += len(findings)

        for risk_level, data in sorted(risk_counts.items()):
            risk_table.add_row(
                risk_level,
                str(len(data['services'])),
                str(data['resources'])
            )

        self.console.print("\n[bold red]Risk Analysis[/bold red]")
        self.console.print(risk_table)

    def process_account(self, account_info: Dict[str, str]):
        """Process single account with progress tracking"""
        account_id = account_info['id']
        account_name = account_info.get('name', 'Unknown')
        
        self.console.print(f"Processing account: {account_name} ({account_id})")
        
        try:
            session = self.session  # Use current session for single account
            regions = self.get_regions(session)

            for region in regions:
                self.console.print(f"Scanning region: {region}")
                for service in self.falcon_mapping.service_mappings.keys():
                    try:
                        resources = self.discover_resources(session, region, service)
                        with self.results_lock:
                            for resource in resources:
                                resource['AccountId'] = account_id
                                resource['AccountName'] = account_name
                                self.results.append(resource)
                    except Exception as e:
                        self.logger.error(f"Error discovering {service} in {region}: {str(e)}")
                        self.console.print(f"[red]Error discovering {service} in {region}: {str(e)}[/red]")
                        continue

        except Exception as e:
            self.logger.error(f"Error processing account {account_id}: {str(e)}")
            self.console.print(f"[red]Error processing account {account_id}: {str(e)}[/red]")

    def run_discovery(self):
        """Main discovery process"""
        start_time = datetime.datetime.now()
        self.console.print("[bold blue]Starting AWS Asset Discovery and Security Analysis...[/bold blue]")

        try:
            current_account = self.session.client('sts').get_caller_identity()
            account_info = {
                'id': current_account['Account'],
                'name': 'Current Account',
                'email': 'N/A'
            }
            self.process_account(account_info)

            # Analyze security posture
            self.analyze_security_posture()

            # Display results
            self.display_security_recommendations()
            self.display_coverage_summary()

            end_time = datetime.datetime.now()
            duration = end_time - start_time
            self.console.print(f"\n[bold green]Analysis completed in {duration}[/bold green]")

        except Exception as e:
            self.logger.error(f"Fatal error in discovery: {str(e)}")
            self.console.print(f"[bold red]Error: {str(e)}[/bold red]")
            raise

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='AWS Asset Discovery Tool')
    parser.add_argument('--org-wide', action='store_true',
                      help='Run discovery across entire AWS organization')
    parser.add_argument('--account', type=str,
                      help='Specific AWS account ID for discovery')
    parser.add_argument('--role-name', type=str, default='OrganizationAccountAccessRole',
                      help='Role name for cross-account access')
    parser.add_argument('--profile', type=str,
                      help='AWS profile name to use')
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    try:
        discovery = AWSAssetDiscovery(
            org_wide=args.org_wide,
            target_account=args.account,
            master_role_name=args.role_name,
            profile_name=args.profile
        )
        discovery.run_discovery()
    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")
        raise

if __name__ == "__main__":
    main()
