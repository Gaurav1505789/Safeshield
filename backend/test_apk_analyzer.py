from pathlib import Path
import sys

from analyzer.apk_analyzer import analyze_apk


def main():

    print("=" * 60)
    print("SafeShield APK Analyzer Test")
    print("=" * 60)

    # --------------------------------------------------------
    # GET APK PATH FROM COMMAND LINE
    # --------------------------------------------------------

    if len(sys.argv) < 2:
        print("Usage:")
        print('python test_apk_analyzer.py "path\\to\\file.apk"')
        return

    apk_path = Path(sys.argv[1])

    print(f"APK path: {apk_path}")

    if not apk_path.exists():
        print("ERROR: APK file not found!")
        return

    if apk_path.suffix.lower() != ".apk":
        print("ERROR: File is not an APK!")
        return

    print(f"APK found: {apk_path}")
    print(f"File size: {apk_path.stat().st_size:,} bytes")
    print()
    print("Starting analysis...")
    print()

    try:

        result = analyze_apk(str(apk_path))

        print("=" * 60)
        print("ANALYSIS RESULT")
        print("=" * 60)

        for key, value in result.items():
            print(f"{key}: {value}")

    except Exception as e:

        print("=" * 60)
        print("ANALYSIS FAILED")
        print("=" * 60)
        print(type(e).__name__)
        print(str(e))


if __name__ == "__main__":
    main()