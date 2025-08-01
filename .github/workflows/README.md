# GitHub Actions Workflows

This directory contains GitHub Actions workflows for CI/CD automation.

## Workflows

### CI Workflow (`ci.yml`)

**Triggers:**
- Pull requests to `main` and `dev` branches
- Pushes to `main` and `dev` branches

**Jobs:**
1. **Test Job:**
   - Runs on Ubuntu with Python 3.12 and 3.13
   - Installs dependencies using `uv`
   - Runs linting (ruff, black)
   - Runs type checking (mypy)
   - Runs unit tests with coverage
   - Uploads coverage to Codecov

2. **Integration Test Job:**
   - Runs only on pull requests
   - Builds binary using `make binary`
   - Runs basic integration test checks
   - Verifies binary creation and basic functionality

### Release Workflow (`release.yml`)

**Triggers:**
- When a release is published on GitHub

**Jobs:**
1. **Build and Release Job:**
   - Runs on Linux (Ubuntu x86_64 and aarch64)
   - Uses dedicated aarch64 runners for ARM64 builds
   - Builds platform-specific binaries for x86_64 and aarch64 architectures
   - Creates compressed archives for each platform and architecture
   - Uploads artifacts for later use

**Note:** We currently only provide Linux builds due to GitHub Actions pricing considerations:
- **Linux runners**: $0.008/minute (1x multiplier)
- **Windows runners**: $0.016/minute (2x multiplier)
- **macOS runners**: $0.08/minute (10x multiplier)

According to [GitHub Actions billing documentation](https://docs.github.com/en/billing/concepts/product-billing/github-actions), Windows and macOS runners consume minutes at 2x and 10x the rate of Linux runners respectively, making them significantly more expensive for CI/CD builds. Linux builds provide the best cost-performance ratio while covering the majority of our target users.

2. **Create Source Archive Job:**
   - Creates a source code archive from the git repository
   - Includes the version tag in the archive name

3. **Publish Release Job:**
   - Downloads all build artifacts
   - Creates a GitHub release with all assets
   - Uploads binaries and source archives to the release



## Required Secrets

No additional secrets are required for the basic release workflow.

## Setup Instructions

1. **Enable GitHub Actions:**
   - Go to your repository settings
   - Navigate to Actions > General
   - Enable "Allow all actions and reusable workflows"



2. **Create a Release:**
   - Create and push a tag: `git tag v1.0.0 && git push origin v1.0.0`
   - Go to GitHub repository > Releases
   - Create a new release from the tag
   - The workflow will automatically run and publish assets

## Artifacts

The release workflow creates the following artifacts:

- `lacpd-linux-x86_64.tar.gz` - Linux x86_64 binary
- `lacpd-linux-aarch64.tar.gz` - Linux ARM64 binary
- `lacpd-{version}-source.tar.gz` - Source code archive

**Platform Support:** Currently, we only provide Linux binaries due to GitHub Actions cost considerations. Users requiring Windows or macOS builds can compile from source using the provided source archive.

## Local Testing

To test the workflows locally, you can use [act](https://github.com/nektos/act):

```bash
# Install act
brew install act  # macOS
# or download from https://github.com/nektos/act/releases

# Test CI workflow
act pull_request

# Test release workflow (requires a tag)
act release
```