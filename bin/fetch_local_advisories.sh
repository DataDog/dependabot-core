#!/bin/bash

REPO_PATH=""
ECOSYSTEM="RUST"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--ecosystem)
            ECOSYSTEM="$2"
            shift 2
            ;;
        *)
            REPO_PATH="$1"
            shift
            ;;
    esac
done

if [ -z "$REPO_PATH" ]; then
    echo "Usage: $0 [--ecosystem ECOSYSTEM] <repo_path>" >&2
    echo "  ECOSYSTEM: RUST, GRADLE (default: RUST)" >&2
    exit 1
fi

# Map GitHub ecosystem to dependabot package manager
case $ECOSYSTEM in
    RUST)
        PACKAGE_MANAGER="cargo"
        ;;
    GRADLE)
        PACKAGE_MANAGER="gradle"
        ;;
    *)
        echo "Unsupported ecosystem: $ECOSYSTEM" >&2
        echo "Supported: RUST, GRADLE" >&2
        exit 1
        ;;
esac

# Get list of dependencies from the repo
echo "Fetching dependencies from $REPO_PATH using $PACKAGE_MANAGER..." >&2
DEPS=$(cd ~/dd/dependabot-core && SECURITY_ADVISORIES='[]' ruby bin/runner.rb "$PACKAGE_MANAGER" "$REPO_PATH" --dir / --list-deps 2>/dev/null)

if [ -z "$DEPS" ]; then
    echo "No dependencies found" >&2
    exit 1
fi

echo "Found dependencies: $DEPS" >&2
echo "Fetching advisories from GitHub..." >&2

# Fetch advisories for each dependency
echo "["
first=true
for dep in $(echo $DEPS | tr ',' ' '); do
    advisories=$(gh api graphql -f query="
    query {
      securityVulnerabilities(first: 10, ecosystem: $ECOSYSTEM, package: \"$dep\") {
        nodes {
          advisory {
            ghsaId
            withdrawnAt
          }
          package { name }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
    " 2>/dev/null | jq -c '(.data.securityVulnerabilities.nodes // [])[] | select(.advisory.withdrawnAt == null) | {
      "dependency-name": .package.name,
      "affected-versions": [.vulnerableVersionRange],
      "patched-versions": (if .firstPatchedVersion then [.firstPatchedVersion.identifier] else [] end),
      "unaffected-versions": []
    }')

    if [ -n "$advisories" ]; then
        # Process each advisory line
        while IFS= read -r advisory; do
            if [ "$first" = true ]; then
                first=false
            else
                echo ","
            fi
            echo "$advisory"
        done <<< "$advisories"
    fi
done
echo "]"
