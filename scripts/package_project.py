"""
Clean Standalone Distribution Packager & Integrity Verifier.
Creates netsec_compliance_auditor.zip using an explicit safe allowlist.
Strictly excludes .venv, node_modules, .git, cache files, local databases, and temporary logs.
Verifies archive integrity and clean extractability upon completion.
"""

import os
import sys
import zipfile
import tempfile
import subprocess
import shutil

# Explicit allowlist of relative files and directory patterns
INCLUDED_ROOT_FILES = [
    ".env.example",
    ".gitignore",
    "Dockerfile",
    "docker-compose.yml",
    "LICENSE",
    "README.md",
    "pytest.ini",
]

INCLUDED_DIRECTORIES = [
    "backend",
    "frontend",
    "ml",
    "sample_data",
    "docs",
    "scripts",
]

EXCLUDED_DIR_NAMES = {
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".git",
    ".idea",
    ".vscode",
    ".system_generated",
    "dist_test",
}

EXCLUDED_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".zip",
    ".log",
}

EXCLUDED_FILENAMES = {
    ".env",
    ".DS_Store",
    "Thumbs.db",
    "network_audit.db",
}


def should_include_file(rel_path: str) -> bool:
    norm_path = rel_path.replace("\\", "/")
    parts = norm_path.split("/")

    # Check for excluded directory anywhere in path
    for part in parts[:-1]:
        if part in EXCLUDED_DIR_NAMES:
            return False

    filename = parts[-1]
    if filename in EXCLUDED_FILENAMES:
        return False

    _, ext = os.path.splitext(filename)
    if ext.lower() in EXCLUDED_EXTENSIONS:
        return False

    # Check root file or allowed directory
    if len(parts) == 1:
        return filename in INCLUDED_ROOT_FILES

    first_dir = parts[0]
    return first_dir in INCLUDED_DIRECTORIES


def create_package(root_dir: str, output_zip_path: str) -> int:
    print(f"\n==================================================")
    print(f"Creating Production ZIP: {output_zip_path}")
    print(f"==================================================")

    # Remove existing zip if present
    if os.path.exists(output_zip_path):
        os.remove(output_zip_path)

    packed_count = 0
    with zipfile.ZipFile(output_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. Add allowed root files
        for f in INCLUDED_ROOT_FILES:
            full_path = os.path.join(root_dir, f)
            if os.path.exists(full_path):
                arcname = os.path.join("netsec_compliance_auditor", f)
                zf.write(full_path, arcname)
                packed_count += 1

        # 2. Add allowed directories
        for d in INCLUDED_DIRECTORIES:
            dir_full = os.path.join(root_dir, d)
            if not os.path.exists(dir_full):
                continue

            for root, dirs, files in os.walk(dir_full):
                # Prune excluded directories
                dirs[:] = [subdir for subdir in dirs if subdir not in EXCLUDED_DIR_NAMES]

                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, root_dir)
                    if should_include_file(rel_path):
                        arcname = os.path.join("netsec_compliance_auditor", rel_path)
                        zf.write(full_path, arcname)
                        packed_count += 1

    file_size_mb = os.path.getsize(output_zip_path) / (1024 * 1024)
    print(f"Packaged {packed_count} files into {output_zip_path} ({file_size_mb:.2f} MB)")
    return packed_count


def verify_archive(output_zip_path: str):
    print("\n--- Verifying Archive Integrity ---")
    with zipfile.ZipFile(output_zip_path, "r") as zf:
        bad_file = zf.testzip()
        if bad_file:
            raise RuntimeError(f"Corrupted file found in ZIP: {bad_file}")
        print("Archive CRC integrity check: PASSED (zero corrupted entries)")

        namelist = zf.namelist()
        required_checks = [
            "netsec_compliance_auditor/README.md",
            "netsec_compliance_auditor/backend/app/main.py",
            "netsec_compliance_auditor/backend/requirements.txt",
            "netsec_compliance_auditor/backend/tests/test_api.py",
            "netsec_compliance_auditor/backend/tests/test_e2e_samples.py",
            "netsec_compliance_auditor/ml/data/dataset.csv",
            "netsec_compliance_auditor/ml/models/risk_classifier.joblib",
            "netsec_compliance_auditor/ml/models/anomaly_detector.joblib",
            "netsec_compliance_auditor/ml/models/metadata.json",
            "netsec_compliance_auditor/frontend/package.json",
            "netsec_compliance_auditor/sample_data/cisco/cisco_hardened_core.cfg",
            "netsec_compliance_auditor/sample_data/fortinet/fortinet_hardened_edge.conf",
            "netsec_compliance_auditor/sample_data/palo_alto/palo_alto_secure_gw.txt",
        ]

        for req in required_checks:
            assert req in namelist, f"Critical file missing from package: {req}"
        print(f"Critical path verification: PASSED (all {len(required_checks)} checked entries present)")

        # Verify forbidden paths are completely absent
        forbidden_substrings = [".venv", "node_modules", ".git", ".pytest_cache", "__pycache__", "network_audit.db"]
        for name in namelist:
            for forb in forbidden_substrings:
                assert f"/{forb}/" not in name and not name.endswith(f"/{forb}"), f"Forbidden entry leaked into zip: {name}"
        print("Forbidden artifact exclusion check: PASSED (zero virtualenv, node_modules, cache, or local db files)")


if __name__ == "__main__":
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    out_zip = os.path.join(project_root, "netsec_compliance_auditor.zip")
    create_package(project_root, out_zip)
    verify_archive(out_zip)
    print("\nPackage creation and integrity verification successfully completed!")
