from __future__ import annotations

import lzma
import zlib

from .base import ExtractResult

# ---------------------------------------------------------------------------
# stdlib має дві сім'ї streaming decompressor API, які відрізняються у двох
# ключових аспектах:
#
#   сім'я A — zlib.decompressobj:
#     • EOF визначається через bool(dec.unused_data), атрибут .eof відсутній;
#     • при max_length залишок невитраченого вхідного буфера повертається у
#       dec.unconsumed_tail — його треба повернути назад на наступний виклик.
#
#   сім'я B — lzma.LZMADecompressor, bz2.BZ2Decompressor:
#     • EOF визначається через dec.eof (bool);
#     • при max_length внутрішній стан зберігається всередині декомпресора;
#       dec.needs_input == False означає «є ще що видати, подавай b""».
#
# Чому зараз НЕ використовується Adapter-клас:
#   Різниця між сімействами зводиться лише до двох предикатів (_dec_eof,
#   _dec_pending).  Повноцінний Adapter виправданий, коли обсяг адаптації
#   ≥ 10 рядків або коли є потреба у runtime-заміні реалізацій.
#   Зараз це overengineering, який ускладнює читання без будь-якої вигоди.
#
# Коли варто перейти до Adapter:
#   • якщо буде додано ≥ 2 нових алгоритми з суттєво іншим API
#     (наприклад, lz4.frame або lzo, де max_length взагалі відсутній);
#   • якщо знадобиться підміна декомпресора у тестах через протокол;
#   • якщо логіка _dec_eof / _dec_pending зросте понад ~15 рядків.
# ---------------------------------------------------------------------------


def _dec_eof(dec: object) -> bool:
    """Повертає True, якщо стрім завершено.

    lzma / bz2 мають атрибут .eof (bool).
    zlib його не має — EOF визначається через bool(unused_data).

    Важливо: bool(unused_data) не є надійним сигналом для lzma/bz2, оскільки
    якщо стрім закінчився рівно на межі chunk-а, unused_data == b"", але
    eof == True.  Тому перевіряємо .eof першим.
    """
    eof_attr = getattr(dec, "eof", None)
    if eof_attr is not None:
        return bool(eof_attr)
    return bool(dec.unused_data)  # type: ignore[attr-defined]  # zlib-сім'я


def _dec_pending(dec: object) -> bytes | None:
    """Повертає дані для наступного виклику dec.decompress(), якщо декомпресор
    ще не вичерпав свій внутрішній стан після досягнення max_length.

    Повертає:
        bytes — дані для наступного виклику (може бути b"" для lzma/bz2);
        None  — декомпресор очікує нові зовнішні дані (inner loop завершено).

    zlib:      unconsumed_tail містить невитрачений вхідний залишок;
               якщо порожній — нових вхідних даних немає, повертаємо None.
    lzma/bz2:  needs_input == False означає «є внутрішній буфер»;
               подаємо b"", щоб декомпресор його вичерпав.
    """
    tail = getattr(dec, "unconsumed_tail", None)
    if tail is not None:          # zlib-сім'я
        return tail if tail else None
    # lzma / bz2-сім'я
    return b"" if not dec.needs_input else None  # type: ignore[attr-defined]


class _StreamExtractorMixin:
    """Спільна логіка для потокового decompressor-а stdlib.

    Підкласи передають make_decompressor — callable без аргументів, який
    повертає свіжий об'єкт декомпресора (zlib.decompressobj,
    lzma.LZMADecompressor або bz2.BZ2Decompressor).

    Алгоритм _run використовує budget-based підхід: кожен виклик
    dec.decompress() отримує max_length = залишок бюджету, тому жоден
    зайвий байт не алоцюється у Python-heap понад max_output.
    """

    def _run(
        self,
        make_decompressor,
        data: bytes,
        offset: int,
        max_output: int,
        chunk_size: int,
    ) -> ExtractResult:

        dec = make_decompressor()
        out = bytearray()
        budget = max_output          # скільки ще байтів можемо прийняти
        pos = offset
        n = len(data)
        consumed = 0
        found_eof = False

        try:
            while pos < n:
                chunk = data[pos : pos + chunk_size]
                feed: bytes | None = chunk   # що подаємо на поточній ітерації

                # --- inner loop: вичерпуємо внутрішній стан декомпресора ---
                # Потрібен, бо при max_length декомпресор може не просунутись
                # по вхідних даних (особливо zlib із unconsumed_tail).
                while feed is not None:
                    piece = dec.decompress(feed, budget)
                    out += piece
                    budget -= len(piece)

                    if budget == 0:
                        # Точно досягли ліміту — більше не можемо прийняти.
                        # Перевіряємо eof: якщо стрім вже закінчився і
                        # розпакований результат вмістився рівно у budget —
                        # це легальний success.
                        if _dec_eof(dec):
                            found_eof = True
                            unused = getattr(dec, "unused_data", b"") or b""
                            consumed = (pos - offset) + (
                                len(chunk) - len(unused)
                            )
                        break

                    if _dec_eof(dec):
                        found_eof = True
                        unused = getattr(dec, "unused_data", b"") or b""
                        consumed = (pos - offset) + (
                            len(chunk) - len(unused)
                        )
                        break

                    feed = _dec_pending(dec)
                    # feed is None → inner loop завершено, переходимо до
                    # наступного зовнішнього chunk-а

                if found_eof:
                    break

                if budget == 0:
                    # Ліміт вичерпано і EOF не настав
                    return ExtractResult(
                        offset=offset,
                        method=self.method,
                        success=False,
                        error=(
                            f"output exceeded {max_output} byte cap "
                            f"before end-of-stream"
                        ),
                    )

                pos += len(chunk)

            else:
                # Outer loop вичерпав вхід, а EOF-маркер так і не з'явився
                return ExtractResult(
                    offset=offset,
                    method=self.method,
                    success=False,
                    error="reached end of file before end-of-stream marker",
                )

        except (lzma.LZMAError, zlib.error, OSError, ValueError, EOFError) as exc:
            # bz2.BZ2Decompressor не має окремого класу помилки — кидає OSError
            return ExtractResult(
                offset=offset,
                method=self.method,
                success=False,
                error=str(exc),
            )

        return ExtractResult(
            offset=offset,
            method=self.method,
            success=True,
            data=bytes(out),
            consumed=consumed,
            output_size=len(out),
        )
