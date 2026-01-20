#!/bin/bash
# Setup script for dual-remote workflow

echo "Setting up dual GitHub remotes..."

# YOU NEED TO SET THESE:
GITHUB_USERNAME="YOUR_GITHUB_USERNAME"  # Change this!
PRIVATE_REPO="near-groth16-sdk-private"
PUBLIC_REPO="near-groth16-sdk"

# Add private remote (everything goes here)
git remote add private "git@github.com:${GITHUB_USERNAME}/${PRIVATE_REPO}.git"

# Add public remote (code only, no audit files)
git remote add public "git@github.com:${GITHUB_USERNAME}/${PUBLIC_REPO}.git"

# Set default push to private
git remote set-url --push origin private

echo "Remotes configured:"
git remote -v

echo ""
echo "Next steps:"
echo "1. Edit setup-remotes.sh and set GITHUB_USERNAME"
echo "2. Run: bash setup-remotes.sh"
echo "3. Make initial commit: git add . && git commit -m 'Initial commit'"
echo "4. Push to private: git push private main"
echo "5. Create public branch: git checkout -b public && git rm FIXES_APPLIED.md SECURITY_AUDIT.md"
echo "6. Push to public: git push public public:main"
