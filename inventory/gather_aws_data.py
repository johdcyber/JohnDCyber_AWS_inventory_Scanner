# inventory/gather_aws_data.py

import logging
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def create_session(profile: str):
    """Create and return a boto3 session for a given profile."""
    return boto3.Session(profile_name=profile) if profile else boto3.Session()

# --------------------------------------------------------------------
# IAM (with MFA checks)
# --------------------------------------------------------------------
def gather_iam_data(session: boto3.Session) -> Dict[str, Any]:
    """
    Gather IAM data: user/role counts, who has MFA, etc.
    """
    iam_info = {
        "user_count": 0,
        "users": [],
        "users_without_mfa": [],
        "role_count": 0,
        "roles": []
    }
    try:
        iam_client = session.client("iam")

        # List users
        paginator_users = iam_client.get_paginator("list_users")
        for page in paginator_users.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                iam_info["users"].append(username)
                # Check MFA
                mfa_resp = iam_client.list_mfa_devices(UserName=username)
                if not mfa_resp["MFADevices"]:
                    iam_info["users_without_mfa"].append(username)

        iam_info["user_count"] = len(iam_info["users"])

        # List roles
        paginator_roles = iam_client.get_paginator("list_roles")
        for page in paginator_roles.paginate():
            for role in page["Roles"]:
                iam_info["roles"].append(role["RoleName"])
        iam_info["role_count"] = len(iam_info["roles"])

    except (BotoCoreError, ClientError) as e:
        logger.error(f"Error gathering IAM data: {str(e)}")

    return iam_info

# --------------------------------------------------------------------
# S3 (with public bucket check)
# --------------------------------------------------------------------
def gather_s3_data(session: boto3.Session) -> Dict[str, Any]:
    """
    Gather S3 data, including checks for potentially public buckets.
    """
    s3_info = {
        "bucket_count": 0,
        "public_buckets": [],
        "buckets": []
    }
    try:
        s3_client = session.client("s3")
        response = s3_client.list_buckets()
        buckets = response.get("Buckets", [])
        s3_info["bucket_count"] = len(buckets)

        for b in buckets:
            name = b["Name"]
            creation_date = b["CreationDate"]
            try:
                loc_response = s3_client.get_bucket_location(Bucket=name)
                region = loc_response.get("LocationConstraint") or "us-east-1"
            except (BotoCoreError, ClientError):
                region = "Unknown"

            # Check bucket ACL for public grants
            is_public_acl = False
            try:
                acl = s3_client.get_bucket_acl(Bucket=name)
                for grant in acl["Grants"]:
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    if uri.endswith("AllUsers") or uri.endswith("AuthenticatedUsers"):
                        is_public_acl = True
                        break
            except ClientError:
                pass

            # Public Access Block
            public_access_block = None
            try:
                pab = s3_client.get_public_access_block(Bucket=name)
                public_access_block = pab["PublicAccessBlockConfiguration"]
            except ClientError:
                pass

            bucket_info = {
                "Name": name,
                "CreationDate": str(creation_date),
                "Region": region,
                "HasPublicACL": is_public_acl,
                "PublicAccessBlock": public_access_block,
            }
            s3_info["buckets"].append(bucket_info)

            if is_public_acl:
                s3_info["public_buckets"].append(name)

    except (BotoCoreError, ClientError) as e:
        logger.error(f"Error gathering S3 data: {str(e)}")

    return s3_info

# --------------------------------------------------------------------
# Security Hub (High Severity Findings)
# --------------------------------------------------------------------
def gather_security_hub_findings(session: boto3.Session) -> Dict[str, Any]:
    """
    Gather summarized high-severity findings from Security Hub.
    """
    findings_info = {
        "high_severity_count": 0,
        "findings": []
    }
    try:
        sh_client = session.client("securityhub")
        paginator = sh_client.get_paginator("get_findings")
        filters = {
            "SeverityLabel": [
                {
                    "Value": "HIGH",
                    "Comparison": "EQUALS"
                }
            ]
        }
        for page in paginator.paginate(Filters=filters):
            for f in page["Findings"]:
                findings_info["high_severity_count"] += 1
                findings_info["findings"].append({
                    "Title": f.get("Title"),
                    "Description": f.get("Description"),
                    "SeverityLabel": f.get("SeverityLabel"),
                    "Remediation": f.get("Remediation", {}).get("Recommendation", {}).get("Text", "")
                })
    except (BotoCoreError, ClientError) as e:
        logger.warning(f"SecurityHub not enabled or error: {str(e)}")

    return findings_info

# --------------------------------------------------------------------
# Cost & Analytics (Placeholder)
# --------------------------------------------------------------------
def estimate_costs_placeholder() -> Dict[str, Any]:
    """
    Placeholder for cost estimation logic (AWS Cost Explorer or Pricing API).
    """
    return {
        "estimated_monthly_usd": 0.0,
        "notes": "Extend with real AWS Cost Explorer or Pricing integration."
    }

# --------------------------------------------------------------------
# EC2
# --------------------------------------------------------------------
def gather_ec2_data(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    ec2_info = {
        "total_running_instances": 0,
        "region_details": {}
    }
    for region in regions:
        try:
            ec2_client = session.client("ec2", region_name=region)
            paginator = ec2_client.get_paginator("describe_instances")
            running_count = 0
            instance_list = []

            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        state = instance.get("State", {}).get("Name")
                        if state == "running":
                            running_count += 1
                        instance_list.append({
                            "InstanceId": instance.get("InstanceId"),
                            "State": state,
                            "InstanceType": instance.get("InstanceType"),
                            "LaunchTime": str(instance.get("LaunchTime")),
                            "Tags": instance.get("Tags", []),
                        })
            ec2_info["total_running_instances"] += running_count
            ec2_info["region_details"][region] = {
                "instance_count": running_count,
                "instances": instance_list
            }

        except (BotoCoreError, ClientError) as e:
            logger.error(f"Error in region {region} for EC2: {str(e)}")
            ec2_info["region_details"][region] = {
                "instance_count": -1,
                "instances": []
            }
    return ec2_info

# --------------------------------------------------------------------
# ECS
# --------------------------------------------------------------------
def gather_ecs_data(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    ecs_info = {
        "total_clusters": 0,
        "total_running_tasks": 0,
        "region_details": {}
    }
    for region in regions:
        try:
            ecs_client = session.client("ecs", region_name=region)
            clusters_resp = ecs_client.list_clusters()
            cluster_arns = clusters_resp.get("clusterArns", [])

            region_clusters = []
            running_tasks_in_region = 0
            for arn in cluster_arns:
                desc = ecs_client.describe_clusters(clusters=[arn])
                if desc["clusters"]:
                    cluster_data = desc["clusters"][0]
                    tasks_resp = ecs_client.list_tasks(cluster=arn, desiredStatus='RUNNING')
                    running_tasks_count = len(tasks_resp.get("taskArns", []))
                    running_tasks_in_region += running_tasks_count

                    region_clusters.append({
                        "ClusterArn": cluster_data.get("clusterArn"),
                        "ClusterName": cluster_data.get("clusterName"),
                        "Status": cluster_data.get("status"),
                        "RunningTasks": running_tasks_count,
                        "ActiveServices": cluster_data.get("activeServicesCount", 0),
                    })
            ecs_info["region_details"][region] = {
                "cluster_count": len(cluster_arns),
                "running_tasks": running_tasks_in_region,
                "clusters": region_clusters
            }
            ecs_info["total_clusters"] += len(cluster_arns)
            ecs_info["total_running_tasks"] += running_tasks_in_region

        except (BotoCoreError, ClientError) as e:
            logger.error(f"Error in ECS for region {region}: {str(e)}")
            ecs_info["region_details"][region] = {
                "cluster_count": -1,
                "running_tasks": -1,
                "clusters": []
            }
    return ecs_info

# --------------------------------------------------------------------
# RDS
# --------------------------------------------------------------------
def gather_rds_data(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    rds_info = {
        "total_db_instances": 0,
        "region_details": {}
    }
    for region in regions:
        try:
            rds_client = session.client("rds", region_name=region)
            paginator = rds_client.get_paginator("describe_db_instances")
            db_count = 0
            db_list = []

            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    db_count += 1
                    db_list.append({
                        "DBInstanceIdentifier": db["DBInstanceIdentifier"],
                        "Engine": db["Engine"],
                        "DBInstanceClass": db["DBInstanceClass"],
                        "DBInstanceStatus": db["DBInstanceStatus"],
                        "AllocatedStorage": db.get("AllocatedStorage", 0),
                        "MultiAZ": db.get("MultiAZ", False),
                    })
            rds_info["total_db_instances"] += db_count
            rds_info["region_details"][region] = {
                "db_instance_count": db_count,
                "db_instances": db_list
            }
        except (BotoCoreError, ClientError) as e:
            logger.error(f"Error gathering RDS data in {region}: {str(e)}")
            rds_info["region_details"][region] = {
                "db_instance_count": -1,
                "db_instances": []
            }
    return rds_info

# --------------------------------------------------------------------
# DynamoDB
# --------------------------------------------------------------------
def gather_dynamodb_data(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    ddb_info = {
        "total_tables": 0,
        "region_details": {}
    }
    for region in regions:
        try:
            ddb_client = session.client("dynamodb", region_name=region)
            paginator = ddb_client.get_paginator("list_tables")
            region_table_count = 0
            tables_list = []

            for page in paginator.paginate():
                table_names = page.get("TableNames", [])
                region_table_count += len(table_names)
                for tname in table_names:
                    desc = ddb_client.describe_table(TableName=tname)
                    table_desc = desc["Table"]
                    billing_mode = table_desc.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED")
                    tables_list.append({
                        "TableName": tname,
                        "TableStatus": table_desc["TableStatus"],
                        "ItemCount": table_desc.get("ItemCount", 0),
                        "BillingMode": billing_mode,
                        "TableSizeBytes": table_desc.get("TableSizeBytes", 0)
                    })

            ddb_info["total_tables"] += region_table_count
            ddb_info["region_details"][region] = {
                "table_count": region_table_count,
                "tables": tables_list
            }
        except (BotoCoreError, ClientError) as e:
            logger.error(f"Error gathering DynamoDB data in {region}: {str(e)}")
            ddb_info["region_details"][region] = {
                "table_count": -1,
                "tables": []
            }
    return ddb_info

# --------------------------------------------------------------------
# Lambda
# --------------------------------------------------------------------
def gather_lambda_data(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    lambda_info = {
        "total_functions": 0,
        "region_details": {}
    }
    for region in regions:
        try:
            lambda_client = session.client("lambda", region_name=region)
            paginator = lambda_client.get_paginator("list_functions")
            region_func_count = 0
            functions_list = []

            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    region_func_count += 1
                    functions_list.append({
                        "FunctionName": fn["FunctionName"],
                        "Runtime": fn.get("Runtime"),
                        "MemorySize": fn.get("MemorySize"),
                        "LastModified": fn.get("LastModified")
                    })
            lambda_info["total_functions"] += region_func_count
            lambda_info["region_details"][region] = {
                "function_count": region_func_count,
                "functions": functions_list
            }
        except (BotoCoreError, ClientError) as e:
            logger.error(f"Error gathering Lambda data in {region}: {str(e)}")
            lambda_info["region_details"][region] = {
                "function_count": -1,
                "functions": []
            }
    return lambda_info

# --------------------------------------------------------------------
# EKS
# --------------------------------------------------------------------
def gather_eks_data(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    eks_info = {
        "total_clusters": 0,
        "region_details": {}
    }
    for region in regions:
        try:
            eks_client = session.client("eks", region_name=region)
            clusters = eks_client.list_clusters().get("clusters", [])
            eks_info["total_clusters"] += len(clusters)

            cluster_list = []
            for c in clusters:
                desc = eks_client.describe_cluster(name=c)
                cluster_data = desc.get("cluster", {})
                cluster_list.append({
                    "ClusterName": cluster_data.get("name"),
                    "Version": cluster_data.get("version"),
                    "Status": cluster_data.get("status"),
                    "Arn": cluster_data.get("arn"),
                    "CreatedAt": str(cluster_data.get("createdAt")),
                })

            eks_info["region_details"][region] = {
                "cluster_count": len(clusters),
                "clusters": cluster_list
            }
        except (BotoCoreError, ClientError) as e:
            logger.error(f"Error gathering EKS data in {region}: {str(e)}")
            eks_info["region_details"][region] = {
                "cluster_count": -1,
                "clusters": []
            }
    return eks_info

# --------------------------------------------------------------------
# CloudFront
# --------------------------------------------------------------------
def gather_cloudfront_data(session: boto3.Session) -> Dict[str, Any]:
    cf_info = {
        "distribution_count": 0,
        "distributions": []
    }
    try:
        cf_client = session.client("cloudfront")
        paginator = cf_client.get_paginator("list_distributions")
        for page in paginator.paginate():
            dist_list = page.get("DistributionList", {})
            items = dist_list.get("Items", [])
            cf_info["distribution_count"] += len(items)
            for d in items:
                origins = [o["DomainName"] for o in d["Origins"]["Items"]]
                cf_info["distributions"].append({
                    "Id": d["Id"],
                    "DomainName": d["DomainName"],
                    "Status": d["Status"],
                    "Origins": origins
                })
    except (BotoCoreError, ClientError) as e:
        logger.error(f"Error gathering CloudFront data: {str(e)}")

    return cf_info

# --------------------------------------------------------------------
# Load Balancers (ALB/NLB + Classic)
# --------------------------------------------------------------------
def gather_loadbalancers_data(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    lb_info = {
        "total_load_balancers": 0,
        "region_details": {}
    }
    for region in regions:
        region_lbs = []
        try:
            elbv2 = session.client("elbv2", region_name=region)
            paginator_v2 = elbv2.get_paginator("describe_load_balancers")
            for page in paginator_v2.paginate():
                for lb in page["LoadBalancers"]:
                    region_lbs.append({
                        "LoadBalancerArn": lb["LoadBalancerArn"],
                        "DNSName": lb["DNSName"],
                        "Type": lb["Type"],
                        "State": lb["State"]["Code"]
                    })
            elb = session.client("elb", region_name=region)
            paginator_elb = elb.get_paginator("describe_load_balancers")
            for page in paginator_elb.paginate():
                for lb in page["LoadBalancerDescriptions"]:
                    region_lbs.append({
                        "LoadBalancerName": lb["LoadBalancerName"],
                        "DNSName": lb["DNSName"],
                        "Type": "classic",
                        "State": "unknown"
                    })
        except (BotoCoreError, ClientError) as e:
            logger.error(f"Error gathering Load Balancers in {region}: {str(e)}")

        lb_info["region_details"][region] = {
            "count": len(region_lbs),
            "load_balancers": region_lbs
        }
        lb_info["total_load_balancers"] += len(region_lbs)
    return lb_info

# --------------------------------------------------------------------
# Auto Scaling Groups (ASG)
# --------------------------------------------------------------------
def gather_asg_data(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    asg_info = {
        "total_asgs": 0,
        "region_details": {}
    }
    for region in regions:
        region_asgs = []
        try:
            asg_client = session.client("autoscaling", region_name=region)
            paginator = asg_client.get_paginator("describe_auto_scaling_groups")
            for page in paginator.paginate():
                for group in page["AutoScalingGroups"]:
                    region_asgs.append({
                        "AutoScalingGroupName": group["AutoScalingGroupName"],
                        "DesiredCapacity": group["DesiredCapacity"],
                        "MinSize": group["MinSize"],
                        "MaxSize": group["MaxSize"]
                    })
        except (BotoCoreError, ClientError) as e:
            logger.error(f"Error gathering ASG data in {region}: {str(e)}")

        asg_info["region_details"][region] = {
            "asg_count": len(region_asgs),
            "asgs": region_asgs
        }
        asg_info["total_asgs"] += len(region_asgs)
    return asg_info


# --------------------------------------------------------------------
# Master aggregator
# --------------------------------------------------------------------
def gather_all_data(profile: str, regions: List[str]) -> Dict[str, Any]:
    """
    Orchestrates data gathering from multiple AWS services,
    including security checks (IAM, S3, Security Hub).
    """
    session = create_session(profile)

    # Security-related
    iam_data = gather_iam_data(session)
    s3_data = gather_s3_data(session)
    sec_hub_data = gather_security_hub_findings(session)
    cost_data = estimate_costs_placeholder()

    # Traditional inventory
    ec2_data = gather_ec2_data(session, regions)
    ecs_data = gather_ecs_data(session, regions)
    rds_data = gather_rds_data(session, regions)
    ddb_data = gather_dynamodb_data(session, regions)
    lambda_data = gather_lambda_data(session, regions)
    eks_data = gather_eks_data(session, regions)
    cf_data = gather_cloudfront_data(session)
    lb_data = gather_loadbalancers_data(session, regions)
    asg_data = gather_asg_data(session, regions)

    return {
        "iam": iam_data,
        "s3": s3_data,
        "securityhub": sec_hub_data,
        "cost": cost_data,
        "ec2": ec2_data,
        "ecs": ecs_data,
        "rds": rds_data,
        "dynamodb": ddb_data,
        "lambda": lambda_data,
        "eks": eks_data,
        "cloudfront": cf_data,
        "loadbalancers": lb_data,
        "autoscaling": asg_data,
    }
