"""
Simulated Snowflake Data Warehouse Adapter.
Simulates: PROD_CUSTOMER_DW.CRM.CUSTOMER_RECORDS
Returns realistic, unmasked customer records containing sensitive PII.
"""
from typing import Any, Dict

MOCK_SNOWFLAKE_WAREHOUSE: Dict[str, Dict[str, Any]] = {
    "CUST-9921": {
        "customer_id": "CUST-9921",
        "full_name": "Jordan Hayes",
        "email": "jordan.hayes@example.com",
        "phone": "+1-555-019-2834",
        "credit_card": "4532-8921-3312-9011",
        "ssn": "000-12-3456",
        "billing_address": "742 Evergreen Terrace, Springfield, OR 97477",
        "account_tier": "VIP_PLATINUM",
        "lifetime_spend": 14250.75,
        "_source": "SNOWFLAKE:PROD_CUSTOMER_DW.CRM.CUSTOMER_RECORDS",
    },
    "CUST-1042": {
        "customer_id": "CUST-1042",
        "full_name": "Elena Rostova",
        "email": "elena.rostova@example.com",
        "phone": "+1-555-014-9912",
        "credit_card": "3782-8224-6310-0051",
        "ssn": "000-45-6789",
        "billing_address": "100 Industrial Pkwy, Austin, TX 78701",
        "account_tier": "STANDARD",
        "lifetime_spend": 820.00,
        "_source": "SNOWFLAKE:PROD_CUSTOMER_DW.CRM.CUSTOMER_RECORDS",
    },
}

def query_customer_record(customer_id: str) -> Dict[str, Any]:
    """Simulates: SELECT * FROM PROD_CUSTOMER_DW.CRM.CUSTOMER_RECORDS WHERE CUSTOMER_ID = %s"""
    return MOCK_SNOWFLAKE_WAREHOUSE.get(
        customer_id,
        {
            "customer_id": customer_id,
            "error": "Record not found in Snowflake warehouse",
            "_source": "SNOWFLAKE:PROD_CUSTOMER_DW.CRM.CUSTOMER_RECORDS",
        },
    )