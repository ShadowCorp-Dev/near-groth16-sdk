# Development Workflow

## Dual-Remote Setup (Public + Private GitHub)

This repository uses **two GitHub remotes** to separate public code from private audit materials.

### Setup

```bash
# Add private repo (full access to everything)
git remote add private git@github.com:YOUR_USERNAME/near-groth16-sdk-private.git

# Add public repo (code only, no sensitive audit files)
git remote add public git@github.com:YOUR_USERNAME/near-groth16-sdk.git

# Verify remotes
git remote -v
```

### Branch Strategy

**Main branch** (private): Contains everything
- Source code
- Audit reports (`FIXES_APPLIED.md`, `SECURITY_AUDIT.md`)
- Internal documentation
- Vulnerability analysis
- Circuit designs

**Public branch**: Clean code for open source
- Source code and templates
- Public documentation (README, circuit guides)
- Examples and tests
- **NO** audit reports or vulnerability details

### Workflow

#### 1. Normal Development (Push to Private)

```bash
git add .
git commit -m "Your changes"
git push private main
```

#### 2. Public Release (Selective Push)

Create a clean public branch without sensitive files:

```bash
# Create public branch from main
git checkout -b public

# Remove sensitive files
git rm FIXES_APPLIED.md SECURITY_AUDIT.md VULNERABILITIES.md
git rm -r audits/ internal-docs/ 2>/dev/null || true

# Commit the removal
git commit -m "Prepare for public release"

# Push to public remote
git push public public:main

# Switch back to main for continued development
git checkout main
```

#### 3. Sync Public Updates

When you make changes that should go public:

```bash
# On main branch
git add templates/ lib/ circuits/ README.md
git commit -m "Public: Add new privacy pool template"
git push private main

# Sync to public branch
git checkout public
git cherry-pick <commit-hash>  # Or: git merge main --no-commit
git rm FIXES_APPLIED.md 2>/dev/null || true  # Ensure sensitive files still removed
git push public public:main
git checkout main
```

### Alternative: Using `git filter-repo` (Recommended for Clean History)

For a cleaner approach, use `git filter-repo` to create a public repo without sensitive history:

```bash
# Install git-filter-repo
pip install git-filter-repo

# Clone your private repo
git clone git@github.com:YOUR_USERNAME/near-groth16-sdk-private.git near-groth16-sdk-public-clean
cd near-groth16-sdk-public-clean

# Remove sensitive files from entire history
git filter-repo --path FIXES_APPLIED.md --invert-paths
git filter-repo --path SECURITY_AUDIT.md --invert-paths
git filter-repo --path VULNERABILITIES.md --invert-paths
git filter-repo --path audits/ --invert-paths
git filter-repo --path internal-docs/ --invert-paths

# Push to public remote
git remote add origin git@github.com:YOUR_USERNAME/near-groth16-sdk.git
git push -u origin main
```

## File Organization

### Private Repo Only
- `FIXES_APPLIED.md` - Detailed vulnerability fixes
- `SECURITY_AUDIT.md` - Full audit reports
- `VULNERABILITIES.md` - Known issues and mitigations
- `audits/` - External audit reports
- `internal-docs/` - Internal design documents

### Both Repos
- `lib/` - Groth16 verifier library
- `templates/` - Smart contract templates
- `circuits/` - Circom circuit examples
- `README.md` - Public documentation
- `examples/` - Usage examples
- `tests/` - Test suites

## Security Notes

- **NEVER** push sensitive files to public remote
- **ALWAYS** review commits before pushing to public
- Keep vulnerability details private until fixes are deployed
- Use private repo for security discussions
