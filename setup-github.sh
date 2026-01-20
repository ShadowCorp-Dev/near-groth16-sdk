#!/bin/bash
set -e

GITHUB_USER="ShadowCorp-Dev"
PRIVATE_REPO="near-groth16-sdk-private"
PUBLIC_REPO="near-groth16-sdk"

echo "🔧 Setting up dual GitHub remotes for $GITHUB_USER..."

# Add SSH remotes
git remote add private "git@github.com:${GITHUB_USER}/${PRIVATE_REPO}.git" 2>/dev/null || echo "Remote 'private' already exists"
git remote add public "git@github.com:${GITHUB_USER}/${PUBLIC_REPO}.git" 2>/dev/null || echo "Remote 'public' already exists"

echo ""
echo "✅ Remotes configured:"
git remote -v

echo ""
echo "📝 Next steps:"
echo ""
echo "1. Create GitHub repos (if you haven't already):"
echo "   - Go to: https://github.com/new"
echo "   - Create: ${PRIVATE_REPO} (set to PRIVATE)"
echo "   - Create: ${PUBLIC_REPO} (set to PUBLIC)"
echo ""
echo "2. Make initial commit:"
echo "   git add ."
echo "   git commit -m 'Initial commit: ZK privacy contracts with audit files'"
echo ""
echo "3. Push everything to private repo:"
echo "   git branch -M main"
echo "   git push -u private main"
echo ""
echo "4. Create public branch (without sensitive files):"
echo "   git checkout -b public"
echo "   git rm -f FIXES_APPLIED.md SECURITY_AUDIT.md VULNERABILITIES.md"
echo "   git rm -rf audits/ internal-docs/ 2>/dev/null || true"
echo "   git commit -m 'Remove sensitive audit files for public release'"
echo "   git push -u public public:main"
echo ""
echo "5. Switch back to main:"
echo "   git checkout main"
echo ""
echo "Done! 🚀"
