from ..analyzers import (
    analyze_busybox,
    analyze_ffmpeg,
    analyze_openssl,
    analyze_runtime,
    analyze_sdk_symbols,
)

ANALYZERS = {
    "busybox": analyze_busybox,
    "ffmpeg": analyze_ffmpeg,
    "openssl": analyze_openssl,
    "runtime": analyze_runtime,
    "sdk_symbols": analyze_sdk_symbols,
}

def analyze_libraries(strings):

    results = {}

    for name, analyzer in ANALYZERS.items():

        result = analyzer(strings)

        if result is not None:
            results[name] = result

    return results