# John D Cyber's AWS Security & Compliance Inventory Scanner

This tool gathers a **comprehensive** AWS inventory across multiple services (EC2, S3, ECS, RDS, DynamoDB, Lambda, EKS, CloudFront, ALB/NLB, Auto Scaling, IAM, and Security Hub findings), 
then generates a **single HTML report** that includes:
- **Security posture checks** (IAM best practices, S3 public buckets, missing MFA, etc.)
- **Tag compliance** (highlight missing required tags)
- **Cost/usage analytics** (optionally integrate AWS pricing or cost explorer)
- **Robust search features** for easy filtering

## Quick Start

1. **Install** dependencies:
   ```bash
   pip install -r requirements.txt

Copy **.env.example** to **.env** and update AWS_PROFILE, AWS_REGIONS, etc.
### Run:
```bash
python -m inventory.main
````
An HTML report (default: cloud_inventory_report.html) is generated in the project directory.
Docker
Build:
bash
Copy code
docker build -t aws-inventory:latest .
Run:
```bash
docker run --rm \
  -e AWS_PROFILE=default \
  -e AWS_REGIONS="us-east-1,us-west-2" \
  -v ~/.aws:/home/appuser/.aws:ro \
  -v $(pwd):/app/output \
  aws-inventory:latest
 ````
The final HTML report appears in your current directory as cloud_inventory_report.html.

## Tests
We use pytest and moto to mock AWS.
Run tests:
```bash
pytest tests/
```
Extending
Security Hub integration can be expanded to parse medium/low severity findings.
IAM can be extended to check password policies, access key rotation, or wildcard policies.
S3 can parse bucket policies in detail.
Cost can integrate AWS Cost Explorer or the Pricing API for real cost analytics.
Enjoy your AWS Security & Compliance inventory scanning!

python
Copy code

---

## 7. `inventory/__init__.py`

```python
# inventory/__init__.py

"""
AWS Security & Compliance Inventory Scanner.

Collects and reports on various AWS services, including IAM, S3, 
SecurityHub, EC2, ECS, RDS, DynamoDB, Lambda, EKS, CloudFront, 
Load Balancers, ASGs, and more.
"""
