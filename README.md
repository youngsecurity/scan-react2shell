# scan-react2shell

## Summary

Checks for vulnerable versions of React 19.x and Next.js 15.x that use React Server Components (RSC) Flight protocol.

## Overview

This tool scans your project dependencies to identify if you are using vulnerable versions of React 19.x or Next.js 15.x that implement the React Server Components (RSC) Flight protocol. These versions are susceptible to CVE-2025-55182.

Available as both PowerShell and Bash scripts for cross-platform compatibility.

## Scripts

| Script | Platform | Requirements |
|--------|----------|--------------|
| `scan-react2shell.ps1` | Windows, Linux, macOS | PowerShell 5.1+ or PowerShell Core |
| `scan-react2shell.sh` | Linux, macOS, WSL | Bash 4.0+ |

## Usage

### PowerShell

```powershell
# Scan current directory
./scan-react2shell.ps1

# Scan specific path
./scan-react2shell.ps1 -Path "C:\Projects"
```

### Bash

```bash
# Scan current directory
./scan-react2shell.sh

# Scan specific path
./scan-react2shell.sh /path/to/projects
```

## Features

- **Recursive scanning**: Finds all `package.json` files in the target directory and subdirectories
- **node_modules exclusion**: Automatically skips `node_modules` directories
- **Version detection**: Identifies vulnerable React 19.0.0-19.2.0 and Next.js 15.x versions
- **Server Actions detection**: Scans source files for `"use server"` directives
- **RSC package detection**: Checks for `react-server-dom-webpack` and `react-server-dom-esm`
- **Color-coded output**: Visual distinction between vulnerable, safe, and unknown repositories
- **CSV export**: Automatically exports vulnerable repositories to CSV for reporting

## Vulnerability Details

**CVE-2025-55182 (React2Shell)** affects:

| Package | Vulnerable Versions | Fixed Version |
|---------|---------------------|---------------|
| React | 19.0.0 - 19.2.0 | 19.2.1+ |
| Next.js | 15.x (before patch) | 15.2.4+ |

## Output

The scanner categorizes repositories into three groups:

1. **Vulnerable**: Projects using affected React/Next.js versions
2. **Safe**: Projects using React/Next.js but not vulnerable versions
3. **Parse Errors**: Projects where `package.json` could not be parsed

## Remediation

If vulnerable repositories are found:

- **React**: Upgrade to 19.2.1 or later
- **Next.js**: Upgrade to 15.2.4 or later

For more information, see the [official React security advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components).
