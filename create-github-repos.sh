#!/bin/bash
# Optional: Create GitHub repos via API (requires personal access token)

GITHUB_USER="ShadowCorp-Dev"
PRIVATE_REPO="near-groth16-sdk-private"
PUBLIC_REPO="near-groth16-sdk"

# Check if GITHUB_TOKEN is set
if [ -z "$GITHUB_TOKEN" ]; then
    echo "❌ GITHUB_TOKEN not set!"
    echo ""
    echo "To use this script:"
    echo "1. Create a personal access token at: https://github.com/settings/tokens/new"
    echo "   - Scopes needed: repo (full control of private repositories)"
    echo "2. Export it: export GITHUB_TOKEN='your_token_here'"
    echo "3. Run this script again"
    echo ""
    echo "Or just create the repos manually at: https://github.com/new"
    exit 1
fi

echo "🚀 Creating GitHub repositories..."

# Create private repo
echo "Creating private repo: ${PRIVATE_REPO}..."
curl -s -X POST "https://api.github.com/user/repos" \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  -d "{
    \"name\": \"${PRIVATE_REPO}\",
    \"description\": \"NEAR Groth16 SDK - Private repo with audit files\",
    \"private\": true
  }" | jq -r '.html_url // .message'

# Create public repo
echo "Creating public repo: ${PUBLIC_REPO}..."
curl -s -X POST "https://api.github.com/user/repos" \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  -d "{
    \"name\": \"${PUBLIC_REPO}\",
    \"description\": \"NEAR Groth16 SDK - Zero-knowledge proof verifier for NEAR Protocol\",
    \"private\": false
  }" | jq -r '.html_url // .message'

echo ""
echo "✅ Done! Now run: ./setup-github.sh"
