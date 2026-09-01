import json
import hashlib


def normalize_text(value):
    """
    Normalize text values for stable comparison.

    Returns None for empty or unknown-like values.
    """

    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    lowered = value.lower()

    unknown_values = {
        "unknown",
        "none",
        "not identifiable",
        "not found in local oui database"
    }

    if lowered in unknown_values:
        return None

    return lowered


def normalize_fingerprint(fingerprint):
    """
    Convert a raw device fingerprint into a stable
    representation for comparison and deduplication.

    Raw IP addresses and full MAC addresses are not
    included because they are not classification
    features and may change over time.
    """

    ssdp = fingerprint.get(
        "ssdp",
        {}
    )

    normalized_services = []

    for service in fingerprint.get(
        "service_details",
        []
    ):

        normalized_services.append({
            "port": normalize_text(
                service.get("port")
            ),

            "protocol": normalize_text(
                service.get("protocol")
            ),

            "service": normalize_text(
                service.get("service")
            ),

            "product": normalize_text(
                service.get("product")
            ),

            "version": normalize_text(
                service.get("version")
            )
        })

    normalized_services.sort(
        key=lambda item: (
            item.get("port") or "",
            item.get("protocol") or "",
            item.get("service") or "",
            item.get("product") or "",
            item.get("version") or ""
        )
    )

    normalized = {
        "hostname": normalize_text(
            fingerprint.get(
                "hostname"
            )
        ),

        "hostname_source": normalize_text(
            fingerprint.get(
                "hostname_source"
            )
        ),

        "mac_type": normalize_text(
            fingerprint.get(
                "mac_type"
            )
        ),

        "vendor": normalize_text(
            fingerprint.get(
                "vendor"
            )
        ),

        "ssdp": {
            "friendly_name": normalize_text(
                ssdp.get(
                    "friendly_name"
                )
            ),

            "manufacturer": normalize_text(
                ssdp.get(
                    "manufacturer"
                )
            ),

            "model_name": normalize_text(
                ssdp.get(
                    "model_name"
                )
            ),

            "device_type_raw": normalize_text(
                ssdp.get(
                    "device_type_raw"
                )
            )
        },

        "mdns_services": sorted(
            {
                normalize_text(service)
                for service in fingerprint.get(
                    "mdns_services",
                    []
                )
                if normalize_text(service)
            }
        ),

        "open_ports": sorted(
            {
                normalize_text(port)
                for port in fingerprint.get(
                    "open_ports",
                    []
                )
                if normalize_text(port)
            }
        ),

        "services": sorted(
            {
                normalize_text(service)
                for service in fingerprint.get(
                    "services",
                    []
                )
                if normalize_text(service)
            }
        ),

        "service_details": normalized_services
    }

    return normalized


def generate_fingerprint_hash(
    normalized_fingerprint
):
    """
    Generate a stable SHA-256 hash from a normalized
    fingerprint.
    """

    serialized = json.dumps(
        normalized_fingerprint,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()
