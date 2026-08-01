"""
Регресійні тести для analyzers/squashfs.py та extractors/squashfs.py.
"""

from __future__ import annotations

import struct
import unittest
import zlib
import lzma

from mstar_analyzer.analyzers.squashfs import parse_squashfs, SquashFsError
from mstar_analyzer.extractors.squashfs import SquashFsExtractor


class SquashFsBuilder:
    """Helper to build minimal synthetic SquashFS images for testing."""
    def __init__(self, endian="<", block_size=4096, compression="none"):
        self.endian = endian
        self.block_size = block_size
        self.compression = compression
        self.compression_id = {"none": 0, "gzip": 1, "lzma": 2, "lzo": 3, "xz": 4, "lz4": 5, "zstd": 6}.get(compression, 0)
        self.file_data = bytearray()
        self.fragments_data = bytearray()
        self.fragment_entries = bytearray()

        self.inodes_meta = bytearray()
        self.inodes_block_offset = 0
        self.inodes_current_chunk = bytearray()

        self.dir_meta = bytearray()
        self.dir_block_offset = 0
        self.dir_current_chunk = bytearray()

        self.next_inode_num = 1
        self.num_fragments = 0
        self.root_inode_ref = 0
        self.s_major = 4
        self.s_minor = 0

    def _flush_inodes(self):
        if not self.inodes_current_chunk:
            return
        if self.compression == "gzip":
            c = zlib.compress(self.inodes_current_chunk)
            h = len(c)
        elif self.compression in ("xz", "lzma"):
            c = lzma.compress(self.inodes_current_chunk)
            h = len(c)
        else:
            c = self.inodes_current_chunk
            h = len(c) | 0x8000
        self.inodes_meta += struct.pack(self.endian + "H", h) + c
        self.inodes_block_offset = len(self.inodes_meta)
        self.inodes_current_chunk = bytearray()

    def add_inode(self, inode_data: bytes) -> tuple[int, int]:
        if len(self.inodes_current_chunk) + len(inode_data) > 8192:
            self._flush_inodes()
        offset_in_block = len(self.inodes_current_chunk)
        ref = (self.inodes_block_offset << 16) | offset_in_block
        self.inodes_current_chunk += inode_data
        inode_num = self.next_inode_num
        self.next_inode_num += 1
        return inode_num, ref

    def _flush_dir(self):
        if not self.dir_current_chunk:
            return
        if self.compression == "gzip":
            c = zlib.compress(self.dir_current_chunk)
            h = len(c)
        elif self.compression in ("xz", "lzma"):
            c = lzma.compress(self.dir_current_chunk)
            h = len(c)
        else:
            c = self.dir_current_chunk
            h = len(c) | 0x8000
        self.dir_meta += struct.pack(self.endian + "H", h) + c
        self.dir_block_offset = len(self.dir_meta)
        self.dir_current_chunk = bytearray()

    def add_directory(self, entries) -> tuple[int, int, int]:
        if not entries:
            return 0, 0, 0
        groups = {}
        for name, ref, t_type in entries:
            s_block = ref >> 16
            groups.setdefault(s_block, []).append((name, ref & 0xFFFF, t_type))

        dir_bytes = bytearray()
        for s_block, grp in groups.items():
            dir_bytes += struct.pack(self.endian + "III", len(grp) - 1, s_block, 0)
            for name, offset_in_block, t_type in grp:
                name_bytes = name.encode("utf-8")
                dir_bytes += struct.pack(self.endian + "HhHH", offset_in_block, 0, t_type, len(name_bytes) - 1)
                dir_bytes += name_bytes

        if len(self.dir_current_chunk) + len(dir_bytes) > 8192:
            self._flush_dir()

        start_block = self.dir_block_offset
        offset_idx = len(self.dir_current_chunk)
        self.dir_current_chunk += dir_bytes
        return start_block, offset_idx, len(dir_bytes)

    def pack_basic_dir_inode(self, inode_num, start_block, offset_idx, file_size):
        base = struct.pack(self.endian + "HHHHII", 1, 0o755, 0, 0, 0, inode_num)
        dir_data = struct.pack(self.endian + "IIHHI", start_block, 2, file_size, offset_idx, 1)
        return base + dir_data

    def pack_extended_dir_inode(self, inode_num, start_block, offset_idx, file_size):
        base = struct.pack(self.endian + "HHHHII", 8, 0o755, 0, 0, 0, inode_num)
        dir_data = struct.pack(self.endian + "IIIIHHI", 2, file_size, start_block, 1, 0, offset_idx, 0xFFFFFFFF)
        return base + dir_data

    def pack_basic_file_inode(self, inode_num, blocks_start, fragment, frag_offset, file_size, block_sizes):
        base = struct.pack(self.endian + "HHHHII", 2, 0o644, 0, 0, 0, inode_num)
        reg_data = struct.pack(self.endian + "IIII", blocks_start, fragment, frag_offset, file_size)
        sizes_data = struct.pack(self.endian + f"{len(block_sizes)}I", *block_sizes)
        return base + reg_data + sizes_data

    def pack_extended_file_inode(self, inode_num, blocks_start, fragment, frag_offset, file_size, block_sizes):
        base = struct.pack(self.endian + "HHHHII", 9, 0o644, 0, 0, 0, inode_num)
        reg_data = struct.pack(self.endian + "QQQIIII", blocks_start, file_size, 0, 1, fragment, frag_offset, 0xFFFFFFFF)
        sizes_data = struct.pack(self.endian + f"{len(block_sizes)}I", *block_sizes)
        return base + reg_data + sizes_data

    def pack_basic_symlink_inode(self, inode_num, target):
        base = struct.pack(self.endian + "HHHHII", 3, 0o777, 0, 0, 0, inode_num)
        target_bytes = target.encode("utf-8")
        sym_data = struct.pack(self.endian + "II", 1, len(target_bytes))
        return base + sym_data + target_bytes

    def pack_extended_symlink_inode(self, inode_num, target):
        base = struct.pack(self.endian + "HHHHII", 10, 0o777, 0, 0, 0, inode_num)
        target_bytes = target.encode("utf-8")
        sym_data = struct.pack(self.endian + "III", 1, len(target_bytes), 0xFFFFFFFF)
        return base + sym_data + target_bytes

    def add_file(self, data: bytes, extended=False):
        blocks_start = 96 + len(self.file_data)
        file_size = len(data)
        block_sizes = []
        for i in range(0, file_size, self.block_size):
            chunk = data[i:i+self.block_size]
            self.file_data += chunk
            block_sizes.append(len(chunk) | 0x1000000)

        inode_num = self.next_inode_num
        if extended:
            inode_data = self.pack_extended_file_inode(inode_num, blocks_start, 0xFFFFFFFF, 0, file_size, block_sizes)
        else:
            inode_data = self.pack_basic_file_inode(inode_num, blocks_start, 0xFFFFFFFF, 0, file_size, block_sizes)
        return self.add_inode(inode_data)

    def add_sparse_file(self, size: int):
        blocks_start = 96 + len(self.file_data)
        num_blocks = (size + self.block_size - 1) // self.block_size
        block_sizes = [0] * num_blocks
        inode_data = self.pack_basic_file_inode(self.next_inode_num, blocks_start, 0xFFFFFFFF, 0, size, block_sizes)
        return self.add_inode(inode_data)

    def add_fragment_file(self, data: bytes):
        frag_idx = self.num_fragments
        self.num_fragments += 1

        f_start_block = 96 + len(self.file_data) + len(self.fragments_data)
        size = len(data) | 0x1000000
        self.fragments_data += data
        self.fragment_entries += struct.pack(self.endian + "QII", f_start_block, size, 0)

        blocks_start = 96 + len(self.file_data)
        inode_data = self.pack_basic_file_inode(self.next_inode_num, blocks_start, frag_idx, 0, len(data), [])
        return self.add_inode(inode_data)

    def build(self) -> bytes:
        self._flush_inodes()
        self._flush_dir()

        image = bytearray(96)

        image += self.file_data
        image += self.fragments_data

        inode_table_start = len(image)
        if not self.inodes_meta:
            self.inodes_current_chunk = b"\x00" * 16
            self._flush_inodes()
        image += self.inodes_meta

        dir_table_start = len(image)
        if not self.dir_meta:
            self.dir_current_chunk = b"\x00" * 16
            self._flush_dir()
        image += self.dir_meta

        if self.fragment_entries:
            c = self.fragment_entries
            h = len(c) | 0x8000
            meta_block = struct.pack(self.endian + "H", h) + c
            meta_block_offset = len(image)
            image += meta_block
            fragment_table_start = len(image)
            image += struct.pack(self.endian + "Q", meta_block_offset)
        else:
            fragment_table_start = len(image)

        sb = struct.pack(
            self.endian + "IIIIIHHHHHHQQQQQQQQ",
            0x73717368, self.next_inode_num - 1, 0, self.block_size, self.num_fragments,
            self.compression_id, 12, 0, 1, self.s_major, self.s_minor,
            self.root_inode_ref, len(image),
            0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
            inode_table_start, dir_table_start, fragment_table_start, 0xFFFFFFFFFFFFFFFF
        )
        magic_bytes = b"hsqs" if self.endian == "<" else b"sqsh"
        image[0:96] = magic_bytes + sb[4:]

        return bytes(image)


class SquashFsSuperblockTests(unittest.TestCase):

    def test_valid_little_endian_image(self):
        b = SquashFsBuilder(endian="<")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, 0, 0, 0))[1]
        img = b.build()
        info, entries = parse_squashfs(img, 0)
        self.assertEqual(info.endian, "little")
        self.assertEqual(info.version, "4.0")
        self.assertEqual(info.inode_count, 1)
        self.assertEqual(info.block_size, 4096)
        self.assertEqual(info.has_xattrs, False)
        self.assertEqual(info.image_size, len(img))

    def test_valid_big_endian_image(self):
        b = SquashFsBuilder(endian=">")
        _, ref = b.add_file(b"hello")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("file", ref, 2)])))[1]
        img = b.build()
        info, entries = parse_squashfs(img, 0)
        self.assertEqual(info.endian, "big")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].data, b"hello")

    def test_invalid_magic_rejected(self):
        b = SquashFsBuilder()
        data = bytearray(b.build())
        data[0:4] = b"badM"
        with self.assertRaisesRegex(SquashFsError, "Invalid magic"):
            parse_squashfs(bytes(data), 0)

    def test_unsupported_squashfs_version_rejected(self):
        b = SquashFsBuilder()
        b.s_major = 3
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, 0, 0, 0))[1]
        with self.assertRaisesRegex(SquashFsError, "Unsupported SquashFS version"):
            parse_squashfs(b.build(), 0)

    def test_truncated_superblock_rejected(self):
        b = SquashFsBuilder()
        data = b.build()[:50]
        with self.assertRaisesRegex(SquashFsError, "Data too short"):
            parse_squashfs(data, 0)

    def test_unsupported_compression_id_is_recorded(self):
        b = SquashFsBuilder()
        b.compression_id = 99
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, 0, 0, 0))[1]
        info, entries = parse_squashfs(b.build(), 0)
        self.assertEqual(info.compression, "unknown")
        self.assertEqual(info.inode_count, 1)
        self.assertEqual(info.block_size, 4096)
        self.assertEqual(info.flags, 0)

    def test_has_xattrs_true_when_xattr_table_present(self):
        b = SquashFsBuilder()
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, 0, 0, 0))[1]
        data = bytearray(b.build())
        # Overwrite xattr_id_table_start (superblock offset 56) with a
        # non-sentinel value to simulate the presence of an xattr table.
        struct.pack_into(b.endian + "Q", data, 56, 0x1000)
        info, _ = parse_squashfs(bytes(data), 0)
        self.assertTrue(info.has_xattrs)


class MetadataReaderTests(unittest.TestCase):

    def test_basic_single_file_traversal(self):
        # Renamed from test_metadata_block_parsing_and_cache: this test
        # verifies that a single-file SquashFS image is correctly parsed
        # and traversed. Cache reuse (MetadataReader.cache) is not
        # observable via the public parse_squashfs() API alone.
        b = SquashFsBuilder()
        _, ref = b.add_file(b"A" * 10)
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("file", ref, 2)])))[1]
        info, entries = parse_squashfs(b.build(), 0)
        self.assertEqual(len(entries), 1)

    def test_compressed_metadata_gzip(self):
        b = SquashFsBuilder(compression="gzip")
        _, ref = b.add_file(b"test gzip")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("file", ref, 2)])))[1]
        info, entries = parse_squashfs(b.build(), 0)
        self.assertEqual(entries[0].data, b"test gzip")

    def test_compressed_metadata_xz(self):
        b = SquashFsBuilder(compression="xz")
        _, ref = b.add_file(b"test xz")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("file", ref, 2)])))[1]
        info, entries = parse_squashfs(b.build(), 0)
        self.assertEqual(entries[0].data, b"test xz")

    def test_truncated_metadata_block_rejected(self):
        b = SquashFsBuilder()
        _, ref = b.add_file(b"A")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("file", ref, 2)])))[1]
        data = bytearray(b.build())
        with self.assertRaisesRegex(SquashFsError, "Truncated metadata"):
            parse_squashfs(bytes(data[:-10]), 0)

    def test_metadata_spanning_block_boundaries(self):
        # 260 file inodes × 36 bytes each = 9360 bytes, which exceeds the
        # 8192-byte metadata block threshold, forcing a multi-block inode
        # table flush. Verifies MetadataReader.read_bytes() correctly
        # traverses compressed metadata blocks that span block boundaries.
        b = SquashFsBuilder()
        dir_entries = []
        for i in range(260):
            _, ref = b.add_file(b"A")
            dir_entries.append((f"f_{i}", ref, 2))
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory(dir_entries)))[1]
        img = b.build()
        info, parsed_entries = parse_squashfs(img, 0)
        self.assertEqual(len(parsed_entries), 260)
        # Verify SquashFsInfo fields for the multi-block case
        self.assertEqual(info.inode_count, 261)  # 260 files + 1 root dir
        self.assertEqual(info.block_size, 4096)
        self.assertEqual(info.image_size, len(img))

    def test_parse_squashfs_with_offset(self):
        # Verify that parse_squashfs respects the offset parameter:
        # internal table lookups (inode_table_start, directory_table_start,
        # fragment_table_start) are all correct when the SquashFS image
        # is embedded at a non-zero offset in a larger buffer.
        b = SquashFsBuilder()
        _, ref = b.add_file(b"offset test")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("file", ref, 2)])))[1]
        img = b.build()
        prefix = b"\xDE\xAD\xBE\xEF" * 100
        data = prefix + img
        offset = len(prefix)

        info, entries = parse_squashfs(data, offset)
        self.assertEqual(info.endian, "little")
        self.assertEqual(info.version, "4.0")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].data, b"offset test")
        self.assertEqual(info.image_size, len(img))


class DirectoryTraversalTests(unittest.TestCase):

    def test_empty_directory(self):
        b = SquashFsBuilder()
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([])))[1]
        info, entries = parse_squashfs(b.build(), 0)
        self.assertEqual(len(entries), 0)

    def test_nested_directories_recursively_traversed(self):
        b = SquashFsBuilder()
        _, ref_f = b.add_file(b"hello")
        _, ref_sub = b.add_inode(b.pack_extended_dir_inode(b.next_inode_num, *b.add_directory([("child.txt", ref_f, 2)])))
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("subdir", ref_sub, 1)])))[1]
        info, entries = parse_squashfs(b.build(), 0)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].name, "subdir/child.txt")

    def test_duplicate_inode_protection_avoids_loops(self):
        b = SquashFsBuilder()
        _, ref_f = b.add_file(b"content")
        _, ref_sub = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("file.txt", ref_f, 2)])))
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([
            ("sub1", ref_sub, 1),
            ("sub2", ref_sub, 1)
        ])))[1]
        info, entries = parse_squashfs(b.build(), 0)
        # Should only contain sub1/file.txt, because sub2 is skipped via seen_inodes
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].name, "sub1/file.txt")

    def test_dot_and_dotdot_entries_ignored(self):
        b = SquashFsBuilder()
        _, ref_f = b.add_file(b"test")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([
            (".", 0, 1),
            ("..", 0, 1),
            ("file.txt", ref_f, 2)
        ])))[1]
        info, entries = parse_squashfs(b.build(), 0)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].name, "file.txt")


class RegularFileTests(unittest.TestCase):

    def test_empty_file(self):
        b = SquashFsBuilder()
        _, ref = b.add_file(b"")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("empty", ref, 2)])))[1]
        info, entries = parse_squashfs(b.build(), 0)
        self.assertEqual(entries[0].size, 0)
        self.assertEqual(entries[0].data, b"")

    def test_single_block_file(self):
        b = SquashFsBuilder(block_size=4096)
        content = b"X" * 100
        _, ref = b.add_file(content)
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("f", ref, 2)])))[1]
        info, entries = parse_squashfs(b.build(), 0)
        self.assertEqual(entries[0].data, content)

    def test_multi_block_file(self):
        b = SquashFsBuilder(block_size=1024)
        content = b"A" * 1024 + b"B" * 1024 + b"C" * 500
        _, ref = b.add_file(content)
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("multi", ref, 2)])))[1]
        info, entries = parse_squashfs(b.build(), 0)
        self.assertEqual(entries[0].data, content)

    def test_fragment_backed_file(self):
        b = SquashFsBuilder()
        _, ref = b.add_fragment_file(b"fragmented data")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("frag", ref, 2)])))[1]
        info, entries = parse_squashfs(b.build(), 0)
        self.assertEqual(entries[0].data, b"fragmented data")

    def test_sparse_blocks(self):
        b = SquashFsBuilder(block_size=4096)
        _, ref = b.add_sparse_file(10000)
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("sparse", ref, 2)])))[1]
        info, entries = parse_squashfs(b.build(), 0)
        self.assertEqual(len(entries[0].data), 10000)
        self.assertEqual(entries[0].data, b"\x00" * 10000)

    def test_extended_file_output_size_verified(self):
        b = SquashFsBuilder()
        _, ref = b.add_file(b"extended", extended=True)
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("ext", ref, 9)])))[1]
        info, entries = parse_squashfs(b.build(), 0)
        self.assertEqual(entries[0].data, b"extended")
        self.assertEqual(entries[0].size, 8)


class KnownLimitationsTests(unittest.TestCase):

    @unittest.expectedFailure
    def test_symlinks_should_be_extracted(self):
        """
        Known limitation:
        Symlink inodes are parsed by read_inode, but traverse() does not
        handle symlink types (3=basic symlink, 10=extended symlink).
        They are silently skipped and not added to extracted_files.
        """
        b = SquashFsBuilder()
        _, ref_sym = b.add_inode(b.pack_basic_symlink_inode(b.next_inode_num, "/etc/passwd"))
        _, ref_esym = b.add_inode(b.pack_extended_symlink_inode(b.next_inode_num, "/bin/sh"))

        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([
            ("sym", ref_sym, 3),
            ("esym", ref_esym, 10)
        ])))[1]

        info, entries = parse_squashfs(b.build(), 0)
        # Desired behaviour: both symlinks should be extracted
        self.assertEqual(len(entries), 2)

    def test_hardlinks_deduplicated_by_design(self):
        """
        Known limitation (by design):
        The `seen_inodes` set in traverse() is intentional — it prevents
        infinite loops from circular directory references. A side-effect is
        that hardlinks (multiple names pointing to the same inode) are
        deduplicated: only the first name is extracted. This is acceptable
        because the file content is still recovered.
        """
        b = SquashFsBuilder()
        _, ref_f = b.add_file(b"shared data")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([
            ("link1", ref_f, 2),
            ("link2", ref_f, 2)
        ])))[1]

        info, entries = parse_squashfs(b.build(), 0)
        # Only the first hardlink is extracted (by design)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].name, "link1")

    def test_unhandled_zlib_error(self):
        """
        Possible implementation issue:
        If zlib.decompress fails even with -15 wbits, it raises zlib.error which is not caught by parse_squashfs.
        It bubbles up to the extractor's catch-all.
        """
        b = SquashFsBuilder(compression="gzip")
        _, ref = b.add_file(b"A")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("a", ref, 2)])))[1]
        data = bytearray(b.build())
        data[-10:] = b"GARBAGE!!!"

        extractor = SquashFsExtractor()
        result = extractor.extract(bytes(data), 0)
        self.assertFalse(result.success)
        self.assertTrue(isinstance(result.error, str))

    def test_unhandled_struct_error_on_fragment_table(self):
        """
        Possible implementation issue:
        If fragment_table_start points near the end of the file, read_bytes will read a truncated pointer.
        struct.unpack("Q") will raise struct.error, which is NOT caught by parse_squashfs!
        The Extractor catches it (as Exception), but it exposes a gap in parser's exception handling.
        """
        b = SquashFsBuilder()
        _, ref = b.add_fragment_file(b"frag")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("f", ref, 2)])))[1]
        data = bytearray(b.build())
        # Corrupt fragment_table_start to point to the very last byte of the image
        data[80:88] = struct.pack(b.endian + "Q", len(data) - 1)

        extractor = SquashFsExtractor()
        result = extractor.extract(bytes(data), 0)
        self.assertFalse(result.success)
        self.assertTrue(isinstance(result.error, str))


class ExtractorTests(unittest.TestCase):

    def test_successful_extraction(self):
        b = SquashFsBuilder()
        _, ref = b.add_file(b"extractor test")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("ext.txt", ref, 2)])))[1]
        data = b.build()

        extractor = SquashFsExtractor()
        img = b"JUNK" + data
        result = extractor.extract(img, 4)

        self.assertTrue(result.success)
        self.assertEqual(result.method, "squashfs")
        self.assertEqual(result.offset, 4)
        self.assertEqual(result.output_size, len(b"extractor test"))
        self.assertEqual(len(result.entries), 1)
        self.assertEqual(result.consumed, len(data))
        self.assertEqual(result.data, data)
        self.assertIn("squashfs", result.metadata)
        self.assertEqual(result.metadata["squashfs"].version, "4.0")

    def test_max_output_rejection(self):
        b = SquashFsBuilder()
        _, ref = b.add_file(b"large file!")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("ext.txt", ref, 2)])))[1]

        extractor = SquashFsExtractor()
        result = extractor.extract(b.build(), 0, max_output=5)

        self.assertFalse(result.success)
        self.assertIn("exceeds max_output", result.error)

    def test_max_output_zero_means_unlimited(self):
        b = SquashFsBuilder()
        _, ref = b.add_file(b"ten bytes")
        b.root_inode_ref = b.add_inode(b.pack_basic_dir_inode(b.next_inode_num, *b.add_directory([("file", ref, 2)])))[1]

        extractor = SquashFsExtractor()
        result = extractor.extract(b.build(), 0, max_output=0)
        self.assertTrue(result.success)

    def test_parser_failures_caught(self):
        extractor = SquashFsExtractor()
        result = extractor.extract(b"totally invalid data!!!!" + b"\x00" * 100, 0)
        self.assertFalse(result.success)
        self.assertIn("Invalid magic", result.error)


if __name__ == "__main__":
    unittest.main()
