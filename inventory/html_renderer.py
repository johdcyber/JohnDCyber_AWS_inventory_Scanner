# inventory/html_renderer.py

import os
from jinja2 import Environment, FileSystemLoader
from typing import Dict, Any

def render_html_report(data: Dict[str, Any], output_file: str):
    """
    Renders an HTML report using Jinja2 templates.
    """
    templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
    env = Environment(loader=FileSystemLoader(templates_dir))
    template = env.get_template("report_template.html")

    rendered_html = template.render(aws_data=data)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(rendered_html)
