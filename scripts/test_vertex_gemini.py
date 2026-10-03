from google import genai

PROJECT_ID = "project-a661dfac-6f3d-4776-a43"
LOCATION = "us-central1"

print(f"[+] Initializing Vertex AI client for {PROJECT_ID} in {LOCATION}...")
client = genai.Client(
    vertexai=True,
    project=PROJECT_ID,
    location=LOCATION,
)

print("[+] Sending test prompt to Gemini 2.5 Flash on Vertex AI...")
response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents="Confirm connectivity: Reply with 'Vertex AI Gemini Connected' and today's status.",
)

print("\n--- Model Response ---")
print(response.text.strip())