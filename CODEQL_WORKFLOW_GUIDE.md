# CodeQL Custom Rule Workflow Guide

## Which Workflow Has the CodeQL Custom Rule?

**Answer: `.github/workflows/codeql.yml` - "CodeQL Email Service Security"**

## Active CodeQL Workflow Details

### Workflow File
- **Path**: `.github/workflows/codeql.yml`
- **Name**: `CodeQL Email Service Security`
- **Trigger**: 
  - Push to main branch (email service files)
  - Pull requests (email service files)
  - Manual workflow dispatch

### Custom Rules Configuration
- **Query Suite**: `.github/codeql/ryudes-python-email/suites/email-security-suite.qls`
- **Custom Rule Pack**: `.github/codeql/ryudes-python-email/`
- **Languages**: Python

### Custom Queries Included
The workflow uses 11 custom CodeQL queries for email security:

1. `EmailHeaderInjection.ql` - Main email header injection detection
2. `EmailHeaderInjectionSimple.ql` - Simplified version
3. `EmailSubjectHeaderInjection.ql` - Subject line injection detection
4. `EmailToHeaderInjection.ql` - To header injection detection
5. `SMTPRecipientInjection.ql` - SMTP recipient injection detection
6. `ProactiveEmailHeaderInjection.ql` - Proactive detection v1
7. `ProactiveV2EmailHeaderInjection.ql` - Proactive detection v2
8. `ProactiveV3EmailHeaderInjection.ql` - Proactive detection v3
9. `EnhancedV21EmailHeaderInjection.ql` - Enhanced version 2.1
10. `EnhancedV21DetailedAlerts.ql` - Detailed alerts v2.1
11. `EnhancedV21Success.ql` - Success tracking v2.1

### File Triggers
The workflow runs when these paths are modified:
- `src/emailservice/**`
- `src/*email*`
- `src/test_*email*`
- `src/test_vulnerabilities.py`

## Disabled Workflow

### What's Disabled
- **Path**: `.github/workflows/ci-main.yaml`
- **Status**: DISABLED (marked as "CodeQL-DISABLED")
- **Reason**: Disabled to avoid conflicts with the custom CodeQL workflow
- **Configuration**: Uses standard CodeQL queries (not custom rules)

## Quick Reference

| Aspect | Active Workflow | Disabled Workflow |
|--------|----------------|-------------------|
| **File** | `codeql.yml` | `ci-main.yaml` |
| **Status** | ✅ Active | ❌ Disabled |
| **Custom Rules** | ✅ Yes (11 queries) | ❌ No (standard only) |
| **Languages** | Python | Go, Python |
| **Scope** | Email service security | General analysis |

## How to Use

### Run the Custom Rule Workflow
1. **Automatic**: Push changes to email service files
2. **Manual**: Go to Actions → "CodeQL Email Service Security" → "Run workflow"

### View Results
- Navigate to the "Security" tab in GitHub
- Check "Code scanning alerts"
- Filter by "CodeQL" to see custom rule findings

## Troubleshooting

### No Custom Rules Running?
- Verify `.github/workflows/codeql.yml` is enabled
- Check that email service files are being modified
- Ensure the query suite file exists: `.github/codeql/ryudes-python-email/suites/email-security-suite.qls`

### Standard CodeQL Running Instead?
- Check if `ci-main.yaml` was re-enabled (it should stay disabled)
- Verify custom workflow is not conflicting with standard CodeQL action

## Documentation References

- Complete implementation guide: `docs/EMAIL_HEADER_INJECTION_GUIDE.md`
- Query documentation: `docs/EMAILHEADERINJECTION_QL_DOCUMENTATION.md`
- AI development guide: `docs/CODEQL_AI_DEVELOPMENT_GUIDE.md`