#!/usr/bin/env bash
# Stop the cost. Deletes the Cloud Run service from YOUR project, or the whole project.
#   bash scripts/teardown_own_copy.sh YOUR_PROJECT_ID            # remove the service only
#   bash scripts/teardown_own_copy.sh YOUR_PROJECT_ID --project  # delete the whole project
set -euo pipefail
LAB_PROJECT="project-a661dfac-6f3d""-4776-a43"
PROJECT="${1:-}"; MODE="${2:-}"; REGION="${REGION:-us-central1}"
[[ -n "$PROJECT" ]] || { echo "usage: $0 YOUR_PROJECT_ID [--project]"; exit 2; }
[[ "$PROJECT" != "$LAB_PROJECT" ]] || { echo "STOP: that is the shared lab project."; exit 1; }
if [[ "$MODE" == "--project" ]]; then
  read -r -p "Type the project id to DELETE the whole project $PROJECT: " ans
  [[ "$ans" == "$PROJECT" ]] || { echo "not confirmed"; exit 1; }
  gcloud projects delete "$PROJECT" --quiet
else
  gcloud run services delete lumen-agent-gateway --region "$REGION" --project "$PROJECT" --quiet
  echo "Service deleted. Firestore, the Model Armor template and the service account remain. Use --project to remove everything."
fi
