from pathlib import Path
import csv
import sys

# ============================================================
# ADD BACKEND DIRECTORY TO PYTHON PATH
# ============================================================

BACKEND_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND_DIR))

from analyzer.apk_analyzer import analyze_apk


# ============================================================
# PATHS
# ============================================================

BENIGN_DIR = BACKEND_DIR / "test_apks" / "benign"
MALICIOUS_DIR = BACKEND_DIR / "test_apks" / "malicious"

OUTPUT_FILE = (
    BACKEND_DIR
    / "ml"
    / "data"
    / "apk_features.csv"
)


# ============================================================
# FEATURE COLUMNS
# ============================================================

FEATURE_COLUMNS = [
    "permission_count",
    "dangerous_permission_count",

    "sms_permission",
    "accessibility_permission",
    "overlay_permission",
    "install_permission",

    "location_permission",
    "camera_permission",
    "microphone_permission",
    "contacts_permission",
    "phone_permission",

    "sms_api",
    "accessibility_api",
    "dynamic_code_loading",
    "runtime_execution",
    "process_builder",
    "overlay_api",

    "sms_behavior",
    "accessibility_behavior",
    "overlay_behavior",
    "dynamic_execution_behavior",

    "activity_count",
    "service_count",
    "receiver_count",
    "provider_count",

    "label"
]


# ============================================================
# GET APK FILES
# ============================================================

def get_apk_files(folder):
    if not folder.exists():
        return []

    return sorted(
        [
            file
            for file in folder.rglob("*")
            if file.is_file()
            and file.suffix.lower() == ".apk"
        ]
    )


# ============================================================
# PROCESS APK
# ============================================================

def process_apk(apk_path, label):

    print(f"Analyzing: {apk_path.name}")
    print(f"  Label: {label}")

    result = analyze_apk(str(apk_path))

    if not result.get("success"):
        print(f"  FAILED: {result.get('error')}")
        print()

        return None

    features = result.get("features", {})

    row = {}

    for column in FEATURE_COLUMNS:

        if column == "label":
            row[column] = label

        else:
            row[column] = features.get(column, 0)

    print(f"  Package: {result.get('package_name')}")
    print(f"  App: {result.get('app_name')}")
    print(f"  Risk score: {result.get('risk_score')}")
    print(f"  Current verdict: {result.get('verdict')}")
    print()

    return row


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("SafeShield APK Dataset Builder")
    print("=" * 60)
    print()

    # --------------------------------------------------------
    # FIND BENIGN APKs
    # --------------------------------------------------------

    benign_apks = get_apk_files(BENIGN_DIR)

    # --------------------------------------------------------
    # FIND MALICIOUS APKs
    # --------------------------------------------------------

    malicious_apks = get_apk_files(MALICIOUS_DIR)

    print(f"Benign APKs found:    {len(benign_apks)}")
    print(f"Malicious APKs found: {len(malicious_apks)}")
    print(f"Total APKs found:     {len(benign_apks) + len(malicious_apks)}")
    print()

    if not benign_apks and not malicious_apks:
        print("No APK files found.")
        print()
        print("Put verified APK samples into:")
        print(f"  {BENIGN_DIR}")
        print(f"  {MALICIOUS_DIR}")
        return

    rows = []

    # --------------------------------------------------------
    # PROCESS BENIGN APKs
    # --------------------------------------------------------

    print("-" * 60)
    print("PROCESSING BENIGN APKs")
    print("-" * 60)

    for apk_path in benign_apks:

        row = process_apk(
            apk_path,
            "benign"
        )

        if row is not None:
            rows.append(row)

    # --------------------------------------------------------
    # PROCESS MALICIOUS APKs
    # --------------------------------------------------------

    print("-" * 60)
    print("PROCESSING MALICIOUS APKs")
    print("-" * 60)

    for apk_path in malicious_apks:

        row = process_apk(
            apk_path,
            "malicious"
        )

        if row is not None:
            rows.append(row)

    # --------------------------------------------------------
    # CHECK RESULTS
    # --------------------------------------------------------

    if not rows:

        print("No APKs were successfully analyzed.")
        return

    # --------------------------------------------------------
    # CREATE OUTPUT DIRECTORY
    # --------------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # WRITE CSV
    # --------------------------------------------------------

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=FEATURE_COLUMNS
        )

        writer.writeheader()
        writer.writerows(rows)

    # --------------------------------------------------------
    # DATASET SUMMARY
    # --------------------------------------------------------

    benign_count = sum(
        row["label"] == "benign"
        for row in rows
    )

    malicious_count = sum(
        row["label"] == "malicious"
        for row in rows
    )

    print()
    print("=" * 60)
    print("DATASET CREATED")
    print("=" * 60)

    print(f"Total rows:     {len(rows)}")
    print(f"Benign samples: {benign_count}")
    print(f"Malicious:      {malicious_count}")
    print()

    print(f"Output:")
    print(OUTPUT_FILE)

    print("=" * 60)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    main()