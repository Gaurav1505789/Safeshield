from pathlib import Path

from analyzer.apk_analyzer import analyze_apk


APK_PATH = Path("test_apks/Sample.apk")


def main():
    print("=" * 60)
    print("SafeShield APK Analyzer Test")
    print("=" * 60)

    print(f"APK path: {APK_PATH}")

    if not APK_PATH.exists():
        print("ERROR: APK file not found!")
        return

    print(f"APK found: {APK_PATH}")
    print(f"File size: {APK_PATH.stat().st_size:,} bytes")
    print()
    print("Starting analysis...")
    print()

    try:
        result = analyze_apk(str(APK_PATH))

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