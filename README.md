# CrowdStrikeAWSAssetDiscovery
## Install the required packages:
'''
pip install boto3 rich
'''

## Make the script executable:
'''
chmod +x aws_asset_discovery.py
'''

## Run the script:
### Basic run
'''
python aws_asset_discovery.py
'''

### With specific AWS profile
'''
python aws_asset_discovery.py --profile your-profile-name
'''

### For organization-wide discovery (if configured)
'''
python aws_asset_discovery.py --org-wide
'''

