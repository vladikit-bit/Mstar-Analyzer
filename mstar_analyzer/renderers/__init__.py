from .ffmpeg import render as render_ffmpeg
from .openssl import render as render_openssl
from .runtime import render as render_runtime
from .sdk_symbols import render as render_sdk_symbols

RENDERERS = {
    "ffmpeg": render_ffmpeg,
    "openssl": render_openssl,
    "runtime": render_runtime,
    "sdk_symbols": render_sdk_symbols,
}