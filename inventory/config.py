# inventory/config.py

import os
from pydantic import BaseSettings, Field
from typing import List

class Settings(BaseSettings):
    """
    Configuration settings loaded from environment variables or .env file.
    """
    aws_profile: str = Field(default="default", env="AWS_PROFILE")
    aws_regions: List[str] = Field(default=["us-east-1"], env="AWS_REGIONS")
    output_file: str = Field(default="cloud_inventory_report.html", env="OUTPUT_FILE")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
