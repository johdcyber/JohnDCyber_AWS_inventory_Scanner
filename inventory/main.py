# inventory/main.py

import logging
import sys
from .config import settings
from .gather_aws_data import gather_all_data
from .html_renderer import render_html_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

def main():
    logger.info("Starting AWS Security & Compliance Inventory Scanner...")

    aws_profile = settings.aws_profile
    aws_regions = settings.aws_regions
    output_file = settings.output_file

    logger.info(f"AWS Profile: {aws_profile}")
    logger.info(f"Regions: {aws_regions}")
    logger.info(f"Output HTML: {output_file}")

    # Gather data
    all_data = gather_all_data(profile=aws_profile, regions=aws_regions)

    # Render HTML
    render_html_report(all_data, output_file)
    logger.info(f"Report generated: {output_file}")

if __name__ == "__main__":
    main()
