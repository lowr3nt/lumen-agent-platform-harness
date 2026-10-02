from google.api_core.client_options import ClientOptions
from google.cloud import modelarmor_v1

PROJECT_ID = "project-a661dfac-6f3d-4776-a43"
LOCATION = "us-central1"
TEMPLATE_ID = "retail-agent-defense"
ENDPOINT = f"modelarmor.{LOCATION}.rep.googleapis.com"
TEMPLATE_PATH = f"projects/{PROJECT_ID}/locations/{LOCATION}/templates/{TEMPLATE_ID}"

client = modelarmor_v1.ModelArmorClient(
    client_options=ClientOptions(api_endpoint=ENDPOINT)
)

# Fetch the existing template
template = client.get_template(name=TEMPLATE_PATH)

# Update filter configuration with PII detection / basic redaction
template_update = {
    "name": TEMPLATE_PATH,
    "filter_config": {
        "pi_and_jailbreak_filter_settings": {
            "filter_enforcement": "ENABLED",
            "confidence_level": "LOW_AND_ABOVE",
        },
        "sdp_settings": {
            "basic_config": {
                "filter_enforcement": "ENABLED"
            }
        }
    }
}

request = {
    "template": template_update,
    "update_mask": {"paths": ["filter_config"]},
}

print(f"Updating template '{TEMPLATE_ID}' to enable Sensitive Data Protection...")
updated = client.update_template(request=request)
print(f"[+] Successfully updated template: {updated.name}")