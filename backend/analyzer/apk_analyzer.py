from pathlib import Path
import hashlib

from loguru import logger
from androguard.core.apk import APK


# ============================================================
# DISABLE ANDROGUARD DEBUG LOGS
# ============================================================

logger.remove()
logger.add(
    lambda msg: None,
    level="WARNING"
)


# ============================================================
# SHA-256
# ============================================================

def calculate_sha256(file_path: str) -> str:
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


# ============================================================
# SUSPICIOUS PERMISSIONS
# ============================================================

SUSPICIOUS_PERMISSIONS = {

    "android.permission.READ_SMS": 15,
    "android.permission.RECEIVE_SMS": 15,
    "android.permission.SEND_SMS": 20,

    "android.permission.CALL_PHONE": 10,

    "android.permission.READ_CALL_LOG": 10,
    "android.permission.WRITE_CALL_LOG": 10,

    "android.permission.READ_CONTACTS": 5,
    "android.permission.WRITE_CONTACTS": 5,

    "android.permission.RECORD_AUDIO": 10,
    "android.permission.CAMERA": 5,

    "android.permission.ACCESS_FINE_LOCATION": 10,
    "android.permission.ACCESS_COARSE_LOCATION": 5,

    "android.permission.READ_PHONE_STATE": 10,

    "android.permission.REQUEST_INSTALL_PACKAGES": 20,

    "android.permission.SYSTEM_ALERT_WINDOW": 15,

    "android.permission.RECEIVE_BOOT_COMPLETED": 10,

    "android.permission.BIND_ACCESSIBILITY_SERVICE": 25,
}


# ============================================================
# HIGH-RISK API INDICATORS
# ============================================================

HIGH_RISK_APIS = {

    "android/telephony/SmsManager": (
        20,
        "SMS sending capability detected"
    ),

    "sendTextMessage": (
        20,
        "SMS sending API detected"
    ),

    "android/accessibilityservice/AccessibilityService": (
        25,
        "Accessibility service detected"
    ),

    "dalvik/system/DexClassLoader": (
        20,
        "Dynamic code loading detected"
    ),

    "dalvik/system/PathClassLoader": (
        10,
        "Runtime class loading detected"
    ),

    "java/lang/ProcessBuilder": (
        15,
        "Process execution capability detected"
    ),

    "java/lang/Runtime": (
        10,
        "Runtime execution capability detected"
    ),

    "android/view/WindowManager": (
        5,
        "Window management capability detected"
    ),
}


# ============================================================
# COMMON / LOW-RISK APIs
# These are features, NOT automatically dangerous.
# ============================================================

COMMON_APIS = {

    "java/net/HttpURLConnection":
        "Network communication detected",

    "okhttp3":
        "OkHttp networking library detected",

    "android/webkit/WebView":
        "WebView usage detected",
}


# ============================================================
# SEARCH DEX FILES
# ============================================================

def get_dex_text(apk):
    """
    Extract readable text from all DEX files.

    Returns one combined string.
    """

    try:

        dex_files = apk.get_all_dex()

        if not dex_files:
            return ""

        text_parts = []

        for dex in dex_files:

            text = dex.decode(
                "utf-8",
                errors="ignore"
            )

            text_parts.append(text)

        return "\n".join(text_parts)

    except Exception:
        return ""


# ============================================================
# API ANALYSIS
# ============================================================

def detect_suspicious_apis(apk):

    findings = []

    dex_text = get_dex_text(apk)

    if not dex_text:
        return findings

    for indicator, data in HIGH_RISK_APIS.items():

        points, description = data

        if indicator in dex_text:

            findings.append({
                "indicator": indicator,
                "risk_points": points,
                "description": description
            })

    return findings


# ============================================================
# COMMON API ANALYSIS
# ============================================================

def detect_common_apis(apk):

    findings = []

    dex_text = get_dex_text(apk)

    if not dex_text:
        return findings

    for indicator, description in COMMON_APIS.items():

        if indicator in dex_text:

            findings.append({
                "indicator": indicator,
                "description": description
            })

    return findings


# ============================================================
# APK FEATURE EXTRACTION
# ============================================================

def extract_features(
    apk,
    permissions,
    api_findings,
    activities,
    services,
    receivers,
    providers
):

    permission_set = set(permissions)

    api_names = {
        item["indicator"]
        for item in api_findings
    }

    # --------------------------------------------------------
    # Permission features
    # --------------------------------------------------------

    dangerous_permission_count = sum(
        permission in SUSPICIOUS_PERMISSIONS
        for permission in permissions
    )

    sms_permission = int(
        any(
            permission in permission_set
            for permission in (
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.SEND_SMS"
            )
        )
    )

    accessibility_permission = int(
        "android.permission.BIND_ACCESSIBILITY_SERVICE"
        in permission_set
    )

    overlay_permission = int(
        "android.permission.SYSTEM_ALERT_WINDOW"
        in permission_set
    )

    install_permission = int(
        "android.permission.REQUEST_INSTALL_PACKAGES"
        in permission_set
    )

    location_permission = int(
        any(
            permission in permission_set
            for permission in (
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION"
            )
        )
    )

    camera_permission = int(
        "android.permission.CAMERA"
        in permission_set
    )

    microphone_permission = int(
        "android.permission.RECORD_AUDIO"
        in permission_set
    )

    contacts_permission = int(
        any(
            permission in permission_set
            for permission in (
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS"
            )
        )
    )

    phone_permission = int(
        any(
            permission in permission_set
            for permission in (
                "android.permission.READ_PHONE_STATE",
                "android.permission.CALL_PHONE"
            )
        )
    )

    # --------------------------------------------------------
    # API features
    # --------------------------------------------------------

    sms_api = int(
        "android/telephony/SmsManager"
        in api_names
        or "sendTextMessage"
        in api_names
    )

    accessibility_api = int(
        "android/accessibilityservice/AccessibilityService"
        in api_names
    )

    dynamic_code_loading = int(
        "dalvik/system/DexClassLoader"
        in api_names
        or "dalvik/system/PathClassLoader"
        in api_names
    )

    runtime_execution = int(
        "java/lang/Runtime"
        in api_names
    )

    process_builder = int(
        "java/lang/ProcessBuilder"
        in api_names
    )

    overlay_api = int(
        "android/view/WindowManager"
        in api_names
    )

    # --------------------------------------------------------
    # Component features
    # --------------------------------------------------------

    service_count = len(services)
    receiver_count = len(receivers)
    provider_count = len(providers)
    activity_count = len(activities)

    # --------------------------------------------------------
    # Combined suspicious signals
    # --------------------------------------------------------

    sms_behavior = int(
        sms_permission == 1
        or sms_api == 1
    )

    accessibility_behavior = int(
        accessibility_permission == 1
        or accessibility_api == 1
    )

    overlay_behavior = int(
        overlay_permission == 1
        or overlay_api == 1
    )

    dynamic_execution_behavior = int(
        dynamic_code_loading == 1
        or runtime_execution == 1
        or process_builder == 1
    )

    # --------------------------------------------------------
    # ML feature dictionary
    # --------------------------------------------------------

    features = {

        # Permissions
        "permission_count": len(permissions),
        "dangerous_permission_count":
            dangerous_permission_count,

        "sms_permission": sms_permission,
        "accessibility_permission":
            accessibility_permission,
        "overlay_permission":
            overlay_permission,
        "install_permission":
            install_permission,
        "location_permission":
            location_permission,
        "camera_permission":
            camera_permission,
        "microphone_permission":
            microphone_permission,
        "contacts_permission":
            contacts_permission,
        "phone_permission":
            phone_permission,

        # APIs
        "sms_api": sms_api,
        "accessibility_api":
            accessibility_api,
        "dynamic_code_loading":
            dynamic_code_loading,
        "runtime_execution":
            runtime_execution,
        "process_builder":
            process_builder,
        "overlay_api":
            overlay_api,

        # Combined behavior
        "sms_behavior": sms_behavior,
        "accessibility_behavior":
            accessibility_behavior,
        "overlay_behavior":
            overlay_behavior,
        "dynamic_execution_behavior":
            dynamic_execution_behavior,

        # Components
        "activity_count":
            activity_count,
        "service_count":
            service_count,
        "receiver_count":
            receiver_count,
        "provider_count":
            provider_count,
    }

    return features


# ============================================================
# RISK SCORE
# ============================================================

def calculate_rule_risk(
    permissions,
    api_findings,
    services,
    receivers,
    providers
):

    risk_score = 0

    # --------------------------------------------------------
    # Permission risk
    # --------------------------------------------------------

    for permission in permissions:

        if permission in SUSPICIOUS_PERMISSIONS:

            risk_score += SUSPICIOUS_PERMISSIONS[
                permission
            ]

    # --------------------------------------------------------
    # API risk
    # --------------------------------------------------------

    for finding in api_findings:

        risk_score += finding["risk_points"]

    # --------------------------------------------------------
    # Component risk
    # --------------------------------------------------------

    if len(services) >= 5:
        risk_score += 5

    if len(receivers) >= 8:
        risk_score += 5

    if len(providers) >= 5:
        risk_score += 5

    # --------------------------------------------------------
    # IMPORTANT COMBINATIONS
    # --------------------------------------------------------

    permission_set = set(permissions)

    sms = any(
        p in permission_set
        for p in (
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS"
        )
    )

    accessibility = (
        "android.permission.BIND_ACCESSIBILITY_SERVICE"
        in permission_set
    )

    overlay = (
        "android.permission.SYSTEM_ALERT_WINDOW"
        in permission_set
    )

    install = (
        "android.permission.REQUEST_INSTALL_PACKAGES"
        in permission_set
    )

    # Multiple dangerous capabilities together
    if sms and accessibility:
        risk_score += 15

    if accessibility and overlay:
        risk_score += 10

    if install and accessibility:
        risk_score += 15

    if sms and install:
        risk_score += 10

    return min(risk_score, 100)


# ============================================================
# VERDICT
# ============================================================

def get_verdict(risk_score):

    if risk_score >= 70:
        return "dangerous"

    if risk_score >= 35:
        return "suspicious"

    return "low_risk"


# ============================================================
# MAIN APK ANALYZER
# ============================================================

def analyze_apk(file_path: str):

    path = Path(file_path)

    # --------------------------------------------------------
    # Validate file
    # --------------------------------------------------------

    if not path.exists():

        return {
            "success": False,
            "error": "APK file not found"
        }

    if path.suffix.lower() != ".apk":

        return {
            "success": False,
            "error": "File is not an APK"
        }

    try:

        # ----------------------------------------------------
        # File information
        # ----------------------------------------------------

        sha256 = calculate_sha256(
            str(path)
        )

        file_size_mb = round(
            path.stat().st_size
            / (1024 * 1024),
            2
        )

        # ----------------------------------------------------
        # Parse APK
        # ----------------------------------------------------

        apk = APK(str(path))

        # ----------------------------------------------------
        # Basic information
        # ----------------------------------------------------

        package_name = apk.get_package()

        app_name = apk.get_app_name()

        version_name = (
            apk.get_androidversion_name()
        )

        version_code = (
            apk.get_androidversion_code()
        )

        # ----------------------------------------------------
        # Permissions
        # ----------------------------------------------------

        permissions = apk.get_permissions()

        suspicious_permissions = []

        for permission in permissions:

            if permission in SUSPICIOUS_PERMISSIONS:

                suspicious_permissions.append({

                    "permission": permission,

                    "risk_points":
                        SUSPICIOUS_PERMISSIONS[
                            permission
                        ]
                })

        # ----------------------------------------------------
        # Components
        # ----------------------------------------------------

        activities = apk.get_activities()

        services = apk.get_services()

        receivers = apk.get_receivers()

        providers = apk.get_providers()

        # ----------------------------------------------------
        # API analysis
        # ----------------------------------------------------

        api_findings = detect_suspicious_apis(
            apk
        )

        common_api_findings = detect_common_apis(
            apk
        )

        # ----------------------------------------------------
        # Rule-based risk
        # ----------------------------------------------------

        risk_score = calculate_rule_risk(

            permissions,

            api_findings,

            services,

            receivers,

            providers
        )

        verdict = get_verdict(
            risk_score
        )

        # ----------------------------------------------------
        # ML FEATURES
        # ----------------------------------------------------

        features = extract_features(

            apk,

            permissions,

            api_findings,

            activities,

            services,

            receivers,

            providers
        )

        # ----------------------------------------------------
        # Result
        # ----------------------------------------------------

        return {

            "success": True,

            "file_name":
                path.name,

            "file_size_mb":
                file_size_mb,

            "sha256":
                sha256,

            "package_name":
                package_name,

            "app_name":
                app_name,

            "version_name":
                version_name,

            "version_code":
                version_code,

            # Permissions
            "permissions":
                permissions,

            "permission_count":
                len(permissions),

            "suspicious_permissions":
                suspicious_permissions,

            # API analysis
            "api_findings":
                api_findings,

            "common_api_findings":
                common_api_findings,

            # Components
            "activities_count":
                len(activities),

            "services_count":
                len(services),

            "receivers_count":
                len(receivers),

            "providers_count":
                len(providers),

            # Risk
            "risk_score":
                risk_score,

            "verdict":
                verdict,

            # ML
            "features":
                features
        }

    except Exception as e:

        return {

            "success": False,

            "error": str(e)
        }