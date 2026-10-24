#!/usr/bin/env bash
# Deploy YOUR OWN copy of the Lumen gateway into YOUR OWN Google Cloud project.
#
#   export JWT_SECRET_KEY="$(openssl rand -hex 24)"     # your own signing secret
#   bash scripts/deploy_own_copy.sh YOUR_PROJECT_ID
#   bash scripts/deploy_own_copy.sh YOUR_PROJECT_ID --redeploy   # after you edit code
#
# What it does, in order: enables APIs, creates a Firestore database, creates a
# service account, creates and tunes the Model Armor template, rewrites the
# hard-coded lab project id in your working copy, and deploys to Cloud Run.
# It costs money in your project. Read the Deploy Your Own Copy guide first.
set -euo pipefail

LAB_PROJECT="project-a661dfac-6f3d""-4776-a43"   # split so the rewrite step never edits this line
PROJECT="${1:-}"
MODE="${2:-}"
REGION="${REGION:-us-central1}"
SERVICE="lumen-agent-gateway"
SA_NAME="sa-lumen-gateway"
PY="${PYTHON_BIN:-python3}"
DRY="${DRY_RUN:-}"

die() { echo "STOP: $*" >&2; exit 1; }
run() { echo "+ $*"; [[ -n "$DRY" ]] || "$@"; }

[[ -n "$PROJECT" ]] || die "usage: $0 YOUR_PROJECT_ID [--redeploy]"
[[ "$PROJECT" != "$LAB_PROJECT" ]] || die "that is the shared lab project. Use your own project id."
[[ -f Makefile && -d gateway ]] || die "run this from the lab folder (cd ~/cloudshell_open/lumen-agent-platform-harness)"
[[ -n "${JWT_SECRET_KEY:-}" ]] || die 'set your own secret first: export JWT_SECRET_KEY="$(openssl rand -hex 24)"'
[[ "$JWT_SECRET_KEY" != "lumen-test-secret-key" ]] || die "that is the public lab secret. The service is public, so anyone could mint admin tokens. Use a new secret."

SA="${SA_NAME}@${PROJECT}.iam.gserviceaccount.com"

echo "Project:  $PROJECT"
echo "Region:   $REGION"
echo "Service:  $SERVICE"
[[ -n "$DRY" ]] && echo "(dry run: commands are printed, not executed)"

if [[ "$MODE" != "--redeploy" ]]; then
  echo; echo "== 1. Project and billing =="
  run gcloud config set project "$PROJECT"
  if [[ -z "$DRY" ]]; then
    gcloud billing projects describe "$PROJECT" --format="value(billingEnabled)" | grep -qi true \
      || die "billing is not enabled on $PROJECT. Link a billing account in the console, then rerun."
  fi

  echo; echo "== 2. Enable APIs (about 1 minute) =="
  run gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
      aiplatform.googleapis.com modelarmor.googleapis.com firestore.googleapis.com \
      logging.googleapis.com monitoring.googleapis.com iam.googleapis.com

  echo; echo "== 3. Firestore database (Native mode) =="
  if [[ -n "$DRY" ]] || ! gcloud firestore databases describe --database="(default)" >/dev/null 2>&1; then
    run gcloud firestore databases create --location="$REGION" --type=firestore-native
  else
    echo "already exists"
  fi

  echo; echo "== 4. Service account and roles =="
  if [[ -n "$DRY" ]] || ! gcloud iam service-accounts describe "$SA" >/dev/null 2>&1; then
    run gcloud iam service-accounts create "$SA_NAME" --display-name="Lumen gateway runtime"
  fi
  for role in roles/modelarmor.user roles/aiplatform.user roles/datastore.user roles/logging.logWriter; do
    run gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${SA}" --role="$role" --condition=None --quiet
  done
  if [[ -z "$DRY" ]]; then
    NUM="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
    # New projects build with the default compute service account. This grant avoids a common build failure.
    gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${NUM}-compute@developer.gserviceaccount.com" \
      --role="roles/cloudbuild.builds.builder" --condition=None --quiet >/dev/null || true
  fi

  echo; echo "== 5. Point the code at your project =="
  FILES="$(grep -rlI --include='*.py' --include='Makefile' --include='cloudbuild.yaml' "$LAB_PROJECT" gateway scripts Makefile cloudbuild.yaml 2>/dev/null | sort -u || true)"
  if [[ -n "$FILES" ]]; then
    git diff --quiet && git diff --cached --quiet || die "you have uncommitted changes. Commit or stash them first, then rerun."
    BR="$(git rev-parse --abbrev-ref HEAD)"
    if [[ "$BR" == "main" ]]; then run git switch -c own-copy; fi
    echo "rewriting the lab project id in:"; echo "$FILES" | sed 's/^/  /'
    [[ -n "$DRY" ]] || echo "$FILES" | xargs sed -i "s/${LAB_PROJECT}/${PROJECT}/g"
  else
    echo "nothing to rewrite (already done)"
  fi

  echo; echo "== 6. Model Armor template (retail-agent-defense) =="
  run "$PY" -m pip install -q -r requirements.txt
  # create_template.py fails if the template exists. That is fine on a rerun.
  if [[ -n "$DRY" ]]; then
    run "$PY" scripts/create_template.py
  else
    "$PY" scripts/create_template.py || echo "(template may already exist, continuing)"
  fi
  run "$PY" scripts/tune_template.py
fi

echo; echo "== Deploy to Cloud Run =="
run gcloud run deploy "$SERVICE" --source . --region "$REGION" --service-account "$SA" \
    --allow-unauthenticated --max-instances=3 --quiet \
    --set-env-vars "GCP_PROJECT_ID=${PROJECT},GCP_LOCATION=${REGION},JWT_SECRET_KEY=${JWT_SECRET_KEY}"

if [[ -z "$DRY" ]]; then
  URL="$(gcloud run services describe "$SERVICE" --region "$REGION" --format='value(status.url)')"
  echo; echo "Deployed: $URL"
  echo "Test it (keep JWT_SECRET_KEY exported in this terminal):"
  echo "  make verify GATEWAY_BASE=$URL HANDLE=yourname"
  echo "  make demo   GATEWAY_BASE=$URL HANDLE=yourname"
fi
