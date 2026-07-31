from .codec_table import render as render_codec_table
from .ffmpeg import render as render_ffmpeg
from .openssl import render as render_openssl
from .runtime import render as render_runtime
from .sdk_symbols import render as render_sdk_symbols

RENDERERS = {
    "codec_table": render_codec_table,
    "ffmpeg": render_ffmpeg,
    "openssl": render_openssl,
    "runtime": render_runtime,
    "sdk_symbols": render_sdk_symbols,
}