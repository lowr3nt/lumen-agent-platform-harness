"""
Simulated Databricks Lakehouse Adapter.
Simulates: delta.`/mnt/analytics/campaign_performance`
"""
from typing import Any, Dict

def query_campaign_metrics(campaign_name: str = "Summer Campaign") -> Dict[str, Any]:
    """Simulates query against a Databricks Delta Lake table."""
    return {
        "campaign_id": "CAMP-SUMMER-2026",
        "campaign_name": campaign_name,
        "impressions": 452100,
        "clicks": 18230,
        "ctr": "4.03%",
        "_source": "DATABRICKS:delta.`/mnt/analytics/campaign_performance`",
    }