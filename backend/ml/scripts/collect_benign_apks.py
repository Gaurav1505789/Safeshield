from pathlib import Path
import hashlib
import shutil


# ============================================================
# SETTINGS
# ============================================================

BACKEND_DIR = Path(__file__).resolve().parents[2]
DOWNLOADS_DIR = Path(r"C:\Users\Pro\Downloads")
BENIGN_DIR = BACKEND_DIR / "test_apks" / "benign"


# ============================================================
# HELPER FUNCTIONS
# ============================================================


def calculate_sha256(file_path):
    """Return the SHA-256 hash of a file as a lowercase hex string."""
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def get_existing_hashes(folder):
    """Build a set of SHA-256 hashes from files already in the benign folder."""
    hashes = set()

    if not folder.exists():
        return hashes

    for item in folder.rglob("*"):
        if item.is_file() and item.suffix.lower() == ".apk":
            try:
                hashes.add(calculate_sha256(item))
            except OSError:
                pass

    return hashes


def make_unique_path(target_folder, original_name):
    """Return a destination path that does not overwrite an existing file."""
    candidate = target_folder / original_name

    if not candidate.exists():
        return candidate

    name = original_name
    stem = Path(name).stem
    suffix = Path(name).suffix
    counter = 1

    while True:
        unique_name = f"{stem}_{counter}{suffix}"
        candidate = target_folder / unique_name

        if not candidate.exists():
            return candidate

        counter += 1


# ============================================================
# MAIN
# ============================================================


def main():
    print("=" * 60)
    print("SafeShield Benign APK Collector")
    print("=" * 60)
    print()
    print("Only place APKs here that you have good reason to consider legitimate.")
    print("Do not use modded, cracked, repacked, or unknown APKs as benign samples.")
    print()

    if not DOWNLOADS_DIR.exists():
        print(f"Downloads folder not found: {DOWNLOADS_DIR}")
        print("Please check the path and try again.")
        return

    BENIGN_DIR.mkdir(parents=True, exist_ok=True)

    found_files = []
    for item in DOWNLOADS_DIR.rglob("*"):
        if item.is_file() and item.suffix.lower() == ".apk":
            found_files.append(item)

    existing_hashes = get_existing_hashes(BENIGN_DIR)
    copied_count = 0
    duplicate_count = 0
    error_count = 0

    print(f"Downloads folder:\n{DOWNLOADS_DIR}")
    print()
    print(f"APK files found: {len(found_files)}")

    for apk_path in found_files:
        try:
            apk_hash = calculate_sha256(apk_path)
        except OSError as error:
            print(f"ERROR: Could not read {apk_path.name}: {error}")
            error_count += 1
            continue

        if apk_hash in existing_hashes:
            duplicate_count += 1
            continue

        destination = make_unique_path(BENIGN_DIR, apk_path.name)

        try:
            shutil.copy2(apk_path, destination)
            existing_hashes.add(apk_hash)
            copied_count += 1
            print(f"Copied: {apk_path} -> {destination}")
        except OSError as error:
            print(f"ERROR: Failed to copy {apk_path.name}: {error}")
            error_count += 1

    print()
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"Downloads folder:\n{DOWNLOADS_DIR}")
    print(f"APK files found: {len(found_files)}")
    print(f"Copied: {copied_count}")
    print(f"Skipped duplicates: {duplicate_count}")
    print(f"Errors: {error_count}")
    print()
    print(f"Benign APK directory:\n{BENIGN_DIR}")


if __name__ == "__main__":
    main()
