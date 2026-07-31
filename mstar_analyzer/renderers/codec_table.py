from __future__ import annotations

from ..analyzers.codec_table import CodecTableProfile


def render(summary: CodecTableProfile) -> None:

    if summary is None or not summary.tables:
        return

    print()
    print("Codec capability table")
    print("-" * 70)

    for table in summary.tables:

        print(f"0x{table.offset:08X}  {len(table.codecs)} recognized codec tag(s)")

        for codec in table.codecs:
            label = table.label_for(codec) or "unrecognized"
            print(f"    {codec:<6} - {label}")

        if table.unrecognized:
            print(
                f"    ({len(table.unrecognized)} unrecognized 4-byte block(s): "
                + ", ".join(table.unrecognized) + ")"
            )

        if table.leftover:
            print(f"    (trailing partial block, not a full fourcc: {table.leftover!r})")
