# tests/test_ec2.py

import pytest
from moto import mock_ec2
import boto3
from inventory.gather_aws_data import gather_ec2_data

@mock_ec2
def test_ec2_data():
    """Test EC2 instance counting with mock."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2")
    ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)

    result = gather_ec2_data(session, ["us-east-1"])
    assert result["total_running_instances"] == 1
    assert result["region_details"]["us-east-1"]["instance_count"] == 1
    assert len(result["region_details"]["us-east-1"]["instances"]) == 1
