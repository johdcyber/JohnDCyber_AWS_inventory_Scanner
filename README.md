JohnDCyber AWS Inventory Scanner

# JohnDCyber AWS Inventory Scanner

JohnDCyber AWS Inventory Scanner is a free, open-source tool that collects a comprehensive inventory of AWS resources across multiple services—while highlighting potential security risks and compliance issues.

## WHY IT’S GREAT

- **Single-pane-of-glass:** Combines EC2, S3, RDS, DynamoDB, ECS, Lambda, EKS, and more in one HTML report.
- **Security & Compliance:** Flags public S3 buckets, IAM users without MFA, Security Hub high-severity findings, etc.
- **Easy to Use:** Run a single Python script (or Docker container) to generate an HTML dashboard.
- **Free & Extensible:** Open-source with the freedom to customize for new services, analytics, or cost data.

## KEY FEATURES

### Multi-Service Inventory
- EC2, S3, ECS, RDS, DynamoDB, Lambda, EKS, CloudFront, Load Balancers, ASGs, etc.  
- Clear separation in a single HTML report.

### Security Focus
- IAM checks for MFA and user details.  
- S3 checks for public bucket ACLs.  
- Security Hub high-severity findings.

### Analytics & Cost
- Placeholder cost estimates (can integrate AWS Cost Explorer).  
- Summaries of resource counts, search filtering for easy usage checks.

### HTML Report with Global Search
- One HTML file with multiple tables.  
- Filter all tables by typing into one search box.

### Docker or Python
- Optionally run via Docker, or install dependencies locally.

## GETTING STARTED

1. **Clone the repository**:
   ```bash
   git clone https://github.com/johdcyber/JohnDCyber_AWS_inventory_Scanner.git
   cd JohnDCyber_AWS_inventory_Scanner
2. Run Locally (Python):
```commandline
  - pip install -r requirements.txt
  - Copy .env.example to .env, update AWS_PROFILE, AWS_REGIONS, OUTPUT_FILE, etc.
  - python -m inventory.main
  - Opens cloud_inventory_report.html in your browser for a full summary.
```
 
3. Run via Docker:
```commandline
  - docker build -t aws-inventory:latest .
   - docker run --rm \
       -e AWS_PROFILE=default \
       -e AWS_REGIONS="us-east-1,us-west-2" \
       -v ~/.aws:/home/appuser/.aws:ro \
       -v $(pwd):/app/output \
       aws-inventory:latest
```
### The HTML report appears in your current directory.

## USAGE & SECURITY

- **AWS Credentials:** Uses local AWS credentials or IAM roles. Store them responsibly.  
- **Visibility & Compliance:** Ideal for security engineers, compliance officers, IT/DevOps teams.  
- **Extensible:** Add new gather functions for more AWS services, integrate deeper cost analytics, or schedule in CI/CD.

## CONTRIBUTING

- Fork this repository, create a branch, add new features or improvements, then submit a Pull Request.  
- Feedback, bug reports, and suggestions are welcome in GitHub Issues:  
  [https://github.com/johdcyber/JohnDCyber_AWS_inventory_Scanner/issues](https://github.com/johdcyber/JohnDCyber_AWS_inventory_Scanner/issues)

## LICENSE

- Provided free for all to use, modify, and adapt. See `LICENSE` for details.

## CONTACT
- **Author**: [https://github.com/johdcyber](https://github.com/johdcyber)
Enjoy the JohnDCyber AWS Inventory Scanner—an easy, free way to secure and manage your AWS environment!
