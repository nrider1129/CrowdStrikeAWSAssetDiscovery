# CrowdStrikeAWSAssetDiscovery
## Install the required packages:
```
pip install boto3 rich
```

## Make the script executable:
```
chmod +x aws_asset_discovery.py
```

## Run the script:
### Basic run
```
python aws_asset_discovery.py
```

### With specific AWS profile
```
python aws_asset_discovery.py --profile your-profile-name
```

## Organization-wide discovery configuration

### Role setup for management account

Create a role with this policy attached in the management account

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "organizations:ListAccounts",
                "organizations:DescribeOrganization",
                "organizations:ListTagsForResource"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::*:role/OrganizationAccountAccessRole"
        }
    ]
}
```
### Role setup for child accounts

Create a role with this policy in child accounts

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeRegions",
                "s3:ListAllMyBuckets",
                "lambda:ListFunctions",
                "rds:DescribeDBInstances",
                "ecs:ListClusters",
                "ecs:DescribeClusters"
            ],
            "Resource": "*"
        }
    ]
},
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::<MANAGEMENT_ACCOUNT_ID>:root"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

### Create config file for additinal customizations (optional)
```
# Create a configuration file named config.json (optional)
{
    "management_account_id": "<YOUR_MANAGEMENT_ACCOUNT_ID>",
    "role_name": "OrganizationAccountAccessRole",
    "excluded_accounts": ["111111111111", "222222222222"],
    "regions": ["us-east-1", "us-west-2"]  # Optional: specify regions to scan
}
```

### AWS CLI config
If using AWS CLI use below steps, if using an assumed role on an EC2 or Cloudshell, skip this step
```
# Configure AWS CLI with management account credentials
aws configure --profile org-scanner

# Set environment variables (optional)
export AWS_PROFILE=org-scanner
export AWS_DEFAULT_REGION=us-east-1
```
### Run the script
```
# Basic organization-wide scan
python aws_asset_discovery.py --org-wide

# With specific role name
python aws_asset_discovery.py --org-wide --role-name CustomRoleName

# With specific profile
python aws_asset_discovery.py --org-wide --profile org-scanner
```

