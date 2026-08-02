"""
Регресійні тести для Jffs2Scanner (signatures.py) та його активації в
build_firmware_map() (firmware_map.py).

Контекст: Jffs2Scanner був повністю реалізований (magic + CRC32-
валідація структури заголовка) і навіть зареєстрований у
DEFAULT_SCANNERS/scan_all() — але жоден виклик build_firmware_map()
його не запускав. scan_all() теж ніде в реальному пайплайні не
викликається. Тобто JFFS2-детекція існувала лише "на папері": жодна
реальна прошивка з JFFS2-розділом ніколи не показала б цього в звіті.

Причина, судячи з коду: попередня реалізація сканувала дані чистим
Python-циклом по КОЖНОМУ байту — на 32 МБ це ~3.1с лише на один
сканер, що й пояснює, чому інтеграцію свідомо відклали.
"""

from __future__ import annotations

import binascii
import os
import random
import struct
import time
import unittest

from mstar_analyzer.firmware_map import MapEntry, _group_jffs2_nodes, build_firmware_map
from mstar_analyzer.signatures import Finding, Jffs2Scanner


def _make_node(nodetype: int, payload: bytes, big_endian: bool = False) -> bytes:
    """
    Будує один валідний (CRC32 header) JFFS2-вузол.

    Сирі magic-байти обираються так, щоб влучити саме в ту гілку
    Jffs2Scanner, яку тестуємо: b"\\x19\\x85" -> endian="<" (little),
    b"\\x85\\x19" -> endian=">" (big). Це внутрішня конвенція самого
    сканера (не плутати з "справжньою" ендіанністю цільового CPU) —
    важлива лише самоузгодженість між заголовком і тим, як його
    декодує scan().
    """

    magic = b"\x85\x19" if big_endian else b"\x19\x85"
    endian = ">" if big_endian else "<"

    totlen = 12 + len(payload)
    header = magic + struct.pack(endian + "HI", nodetype, totlen)
    crc = (binascii.crc32(header, -1) ^ 0xFFFFFFFF) & 0xFFFFFFFF

    return header + struct.pack(endian + "I", crc) + payload


class Jffs2ScannerCorrectnessTests(unittest.TestCase):
    """
    Переконуємось, що оптимізація (iter_find() замість посимвольного
    циклу) не змінила поведінку сканера.
    """

    def test_detects_little_endian_node(self):
        node = _make_node(0xE001, b"x" * 20, big_endian=False)
        found = Jffs2Scanner().scan(node)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].offset, 0)
        self.assertEqual(found[0].name, "JFFS2 node")
        self.assertIn("len=32", found[0].detail)

    def test_detects_big_endian_node(self):
        node = _make_node(0xE001, b"x" * 20, big_endian=True)
        found = Jffs2Scanner().scan(node)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].offset, 0)

    def test_rejects_bad_crc(self):
        node = bytearray(_make_node(0xE001, b"x" * 20))
        node[8] ^= 0xFF  # псуємо один байт CRC-поля заголовка
        self.assertEqual(Jffs2Scanner().scan(bytes(node)), [])

    def test_rejects_truncated_totlen(self):
        # totlen каже, що вузол більший за буфер — має бути відкинутий.
        node = bytearray(_make_node(0xE001, b"x" * 20))
        truncated = bytes(node[:20])  # totlen=32, але даних лише 20
        self.assertEqual(Jffs2Scanner().scan(truncated), [])

    def test_finds_node_at_nonzero_offset(self):
        data = b"\xFF" * 137 + _make_node(0xE002, b"payload!" * 4)
        found = Jffs2Scanner().scan(data)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].offset, 137)

    def test_scan_stays_fast_on_large_random_input(self):
        """
        Регресія на продуктивність: попередня реалізація ("for offset
        in range(len(data))" з посимвольним порівнянням зрізу) давала
        ~3.1с на 32 МБ. iter_find()-версія — ~0.03-0.05с. Межу 0.5с на
        16 МБ узято зі значним запасом для повільнішого CI, але вона
        все одно на порядок нижче того, що дав би старий алгоритм
        (~1.5с на 16 МБ, лінійна екстраполяція).
        """

        data = random.Random(1).randbytes(16_000_000)

        t0 = time.perf_counter()
        Jffs2Scanner().scan(data)
        elapsed = time.perf_counter() - t0

        self.assertLess(elapsed, 0.5, f"scan() took {elapsed:.3f}s — looks like the O(n) per-byte fallback")


class GroupJffs2NodesTests(unittest.TestCase):
    """
    _group_jffs2_nodes() перетворює потенційно тисячі сирих per-node
    Finding на компактні "JFFS2 filesystem region" MapEntry — інакше
    реальний JFFS2-розділ затопив би Firmware map таблицю рядками по
    одному на кожен inode/dirent-заголовок.
    """

    def test_empty_input(self):
        self.assertEqual(_group_jffs2_nodes([]), [])

    def test_single_node_becomes_one_region(self):
        findings = [Finding(offset=100, name="JFFS2 node", confidence="high", detail="type=0xE001 len=32")]
        regions = _group_jffs2_nodes(findings)
        self.assertEqual(len(regions), 1)
        self.assertEqual(regions[0].offset, 100)
        self.assertEqual(regions[0].kind, "JFFS2 filesystem region")
        self.assertIn("1 node,", regions[0].detail)

    def test_contiguous_nodes_collapse_into_one_region(self):
        # 5 вузлів по 32 байти підряд, без проміжків.
        findings = [
            Finding(offset=100 + i * 32, name="JFFS2 node", confidence="high", detail="type=0xE001 len=32")
            for i in range(5)
        ]
        regions = _group_jffs2_nodes(findings)
        self.assertEqual(len(regions), 1)
        self.assertEqual(regions[0].offset, 100)
        self.assertIn("5 nodes,", regions[0].detail)
        self.assertIn("160 bytes", regions[0].detail)  # 5 * 32

    def test_distant_nodes_stay_separate_regions(self):
        findings = [
            Finding(offset=0x1000, name="JFFS2 node", confidence="high", detail="type=0xE001 len=32"),
            Finding(offset=0x9000, name="JFFS2 node", confidence="high", detail="type=0xE001 len=32"),
        ]
        regions = _group_jffs2_nodes(findings)
        self.assertEqual(len(regions), 2)

    def test_small_gap_within_tolerance_still_merges(self):
        # Кінець вузла 1: 100+32=132. Вузол 2 починається на 140
        # (8-байтовий проміжок, напр. padding-вузол) — усередині
        # gap_tolerance за замовчуванням (32).
        findings = [
            Finding(offset=100, name="JFFS2 node", confidence="high", detail="type=0xE001 len=32"),
            Finding(offset=140, name="JFFS2 node", confidence="high", detail="type=0xE001 len=32"),
        ]
        regions = _group_jffs2_nodes(findings)
        self.assertEqual(len(regions), 1)
        self.assertIn("2 nodes,", regions[0].detail)


class Jffs2PipelineIntegrationTests(unittest.TestCase):
    """
    Наскрізна перевірка того, що раніше НІКОЛИ не траплялося: JFFS2
    насправді бере участь у build_firmware_map(), а не лишається
    зареєстрованим, але мертвим кодом.
    """

    def test_contiguous_filesystem_appears_as_single_region_entry(self):
        nodes = b"".join(_make_node(0xE001, os.urandom(20)) for _ in range(50))
        data = b"\xFF" * 200 + nodes + b"\xFF" * 200

        fw = build_firmware_map(data)

        jffs2_entries = [e for e in fw.entries if e.kind == "JFFS2 filesystem region"]
        self.assertEqual(len(jffs2_entries), 1, fw.entries)
        self.assertEqual(jffs2_entries[0].offset, 200)
        self.assertIn("50 nodes,", jffs2_entries[0].detail)

    def test_no_jffs2_data_means_no_jffs2_entries(self):
        data = random.Random(2).randbytes(5000)
        fw = build_firmware_map(data)
        self.assertFalse([e for e in fw.entries if "JFFS2" in e.kind])


if __name__ == "__main__":
    unittest.main()
