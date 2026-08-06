import struct
import zlib
import lzma
from dataclasses import dataclass
from typing import Iterator

from ..extractors.base import FileSystemEntry
from ..lz4_block import decompress_block as _lz4_decompress_block, Lz4BlockError

@dataclass(slots=True)
class SquashFsInfo:
    """Metadata about a parsed SquashFS filesystem."""
    version: str           # e.g. "3.0", "4.0"
    endian: str            # "little" or "big"
    block_size: int        # data block size (4096, 8192, ..., 65536)
    inode_count: int       # total number of inodes
    block_count: int       # total number of data blocks
    compression: str       # "gzip", "xz", "lzma", "lzo", "zstd", "none"
    flags: int             # raw flags field from superblock
    has_xattrs: bool       # whether extended attributes are present
    image_size: int        # total size of the SquashFS image in bytes


class SquashFsError(Exception):
    pass


COMPRESSIONS = {
    1: "gzip",
    2: "lzma",
    3: "lzo",
    4: "xz",
    5: "lz4",
    6: "zstd"
}


def _decompress_block(data: bytes, compression: str) -> bytes:
    if compression == "gzip":
        try:
            return zlib.decompress(data)
        except zlib.error:
            return zlib.decompress(data, -15)
    elif compression in ("xz", "lzma"):
        return lzma.decompress(data)
    elif compression == "lz4":
        # SquashFS зберігає розмір кожного блока у власних inode-
        # метаданих (без жодної LZ4 Frame-обгортки — magic/checksums/
        # per-block size prefixes тут не потрібні й не присутні), тож
        # це сирий LZ4 "block format", той самий декодер, що й
        # extractors/lz4.py використовує для КОЖНОГО блока LZ4 Frame.
        # Кожен блок SquashFS розпаковується незалежно (той самий
        # принцип, що вже застосований тут для gzip/xz вище) — без
        # спільного output-буфера.
        try:
            return _lz4_decompress_block(data)
        except Lz4BlockError as exc:
            raise SquashFsError(f"corrupt LZ4 block: {exc}") from exc
    elif compression == "none":
        return data
    else:
        raise SquashFsError(f"Unsupported compression: {compression}")


class MetadataReader:
    def __init__(self, data: bytes, base_offset: int, endian: str, compression: str):
        self.data = data
        self.base = base_offset
        self.endian = endian
        self.compression = compression
        self.cache = {}

    def read_block_and_size(self, block_start: int):
        if block_start in self.cache:
            return self.cache[block_start]
        
        abs_offset = self.base + block_start
        header_bytes = self.data[abs_offset:abs_offset+2]
        if len(header_bytes) < 2:
            raise SquashFsError("Truncated metadata header")
            
        header = int.from_bytes(header_bytes, self.endian)
        is_uncompressed = bool(header & 0x8000)
        size = header & 0x7FFF
        
        raw_data = self.data[abs_offset+2:abs_offset+2+size]
        if len(raw_data) < size:
            raise SquashFsError("Truncated metadata block")
            
        if is_uncompressed:
            block = raw_data
        else:
            block = _decompress_block(raw_data, self.compression)
            
        res = (block, 2 + size)
        self.cache[block_start] = res
        return res

    def read_bytes(self, block_start: int, block_idx: int, length: int) -> bytes:
        result = bytearray()
        while length > 0:
            block, c_size = self.read_block_and_size(block_start)
            if block_idx >= len(block):
                block_idx -= len(block)
                block_start += c_size
                continue
                
            available = len(block) - block_idx
            take = min(length, available)
            result.extend(block[block_idx:block_idx+take])
            length -= take
            block_idx += take
            if block_idx >= len(block):
                block_idx -= len(block)
                block_start += c_size
        return bytes(result)


def parse_squashfs(data: bytes, offset: int) -> tuple[SquashFsInfo, list[FileSystemEntry]]:
    """
    Parse a SquashFS filesystem starting at `offset` in `data`.
    """
    if len(data) < offset + 96:
        raise SquashFsError("Data too short for SquashFS superblock")

    magic = data[offset:offset+4]
    if magic == b"hsqs":
        endian_fmt = "<"
        endian_str = "little"
    elif magic == b"sqsh":
        endian_fmt = ">"
        endian_str = "big"
    else:
        raise SquashFsError(f"Invalid magic: {magic!r}")

    header_fmt = endian_fmt + "IIIIIHHHHHHQQQQQQQQ"
    try:
        (
            s_magic, inodes, mkfs_time, block_size, fragments,
            compression_id, block_log, flags, no_ids,
            s_major, s_minor,
            root_inode, bytes_used, id_table_start,
            xattr_id_table_start, inode_table_start,
            directory_table_start, fragment_table_start, export_table_start
        ) = struct.unpack(header_fmt, data[offset:offset+96])
    except struct.error:
        raise SquashFsError("Failed to unpack superblock")
    
    if s_major != 4:
        raise SquashFsError(f"Unsupported SquashFS version {s_major}.{s_minor}")

    compression = COMPRESSIONS.get(compression_id, "unknown")
    
    info = SquashFsInfo(
        version=f"{s_major}.{s_minor}",
        endian=endian_str,
        block_size=block_size,
        inode_count=inodes,
        block_count=0, # Not explicitly present in superblock
        compression=compression,
        flags=flags,
        has_xattrs=xattr_id_table_start != 0xffffffffffffffff,
        image_size=bytes_used
    )

    meta_reader = MetadataReader(data, offset, endian_str, compression)

    def read_inode(ref: int):
        block_offset = ref >> 16
        block_idx = ref & 0xFFFF
        
        base_data = meta_reader.read_bytes(inode_table_start + block_offset, block_idx, 16)
        inode_type, mode, uid, guid, mtime, inode_number = struct.unpack(endian_fmt + "HHHHII", base_data)
        
        inode = {
            "type": inode_type,
            "mode": mode,
            "inode_number": inode_number
        }
        
        if inode_type == 1: # Basic Directory
            dir_data = meta_reader.read_bytes(inode_table_start + block_offset, block_idx + 16, 16)
            start_block, nlink, file_size, offset_idx, parent_inode = struct.unpack(endian_fmt + "IIHHI", dir_data)
            inode["start_block"] = start_block
            inode["file_size"] = file_size
            inode["offset"] = offset_idx
            
        elif inode_type == 2: # Basic File
            reg_data = meta_reader.read_bytes(inode_table_start + block_offset, block_idx + 16, 16)
            blocks_start, fragment, frag_offset, file_size = struct.unpack(endian_fmt + "IIII", reg_data)
            inode["blocks_start"] = blocks_start
            inode["fragment"] = fragment
            inode["frag_offset"] = frag_offset
            inode["file_size"] = file_size
            
            if fragment == 0xFFFFFFFF:
                num_blocks = (file_size + block_size - 1) // block_size
            else:
                num_blocks = file_size // block_size
                
            block_sizes_data = meta_reader.read_bytes(inode_table_start + block_offset, block_idx + 32, num_blocks * 4)
            inode["block_sizes"] = struct.unpack(endian_fmt + f"{num_blocks}I", block_sizes_data)
            
        elif inode_type == 8: # Extended Directory
            dir_data = meta_reader.read_bytes(inode_table_start + block_offset, block_idx + 16, 24)
            nlink, file_size, start_block, parent_inode, i_count, offset_idx, xattr = struct.unpack(endian_fmt + "IIIIHHI", dir_data)
            inode["start_block"] = start_block
            inode["file_size"] = file_size
            inode["offset"] = offset_idx

        elif inode_type == 9: # Extended File
            reg_data = meta_reader.read_bytes(inode_table_start + block_offset, block_idx + 16, 40)
            blocks_start, file_size, sparse, nlink, fragment, frag_offset, xattr = struct.unpack(endian_fmt + "QQQIIII", reg_data)
            inode["blocks_start"] = blocks_start
            inode["fragment"] = fragment
            inode["frag_offset"] = frag_offset
            inode["file_size"] = file_size
            
            if fragment == 0xFFFFFFFF:
                num_blocks = (file_size + block_size - 1) // block_size
            else:
                num_blocks = file_size // block_size
                
            block_sizes_data = meta_reader.read_bytes(inode_table_start + block_offset, block_idx + 56, num_blocks * 4)
            inode["block_sizes"] = struct.unpack(endian_fmt + f"{num_blocks}I", block_sizes_data)
            
        elif inode_type == 3: # Basic Symlink
            sym_data = meta_reader.read_bytes(inode_table_start + block_offset, block_idx + 16, 8)
            nlink, symlink_size = struct.unpack(endian_fmt + "II", sym_data)
            target_data = meta_reader.read_bytes(inode_table_start + block_offset, block_idx + 24, symlink_size)
            inode["symlink_target"] = target_data.decode("utf-8", errors="replace")
            
        elif inode_type == 10: # Extended Symlink
            sym_data = meta_reader.read_bytes(inode_table_start + block_offset, block_idx + 16, 12)
            nlink, symlink_size, xattr = struct.unpack(endian_fmt + "III", sym_data)
            target_data = meta_reader.read_bytes(inode_table_start + block_offset, block_idx + 28, symlink_size)
            inode["symlink_target"] = target_data.decode("utf-8", errors="replace")
            
        return inode

    def read_directory(start_block: int, offset_idx: int, file_size: int):
        dir_data = meta_reader.read_bytes(directory_table_start + start_block, offset_idx, file_size)
        entries = []
        pos = 0
        while pos + 12 <= len(dir_data):
            count, s_block, inode_number = struct.unpack(endian_fmt + "III", dir_data[pos:pos+12])
            pos += 12
            
            for _ in range(count + 1):
                if pos + 8 > len(dir_data):
                    break
                offset_in_block, inode_diff, t_type, name_size = struct.unpack(endian_fmt + "HhHH", dir_data[pos:pos+8])
                pos += 8
                
                name_len = name_size + 1
                if pos + name_len > len(dir_data):
                    break
                    
                name_bytes = dir_data[pos:pos+name_len]
                pos += name_len
                
                name = name_bytes.decode("utf-8", errors="replace")
                ref = (s_block << 16) | offset_in_block
                entries.append((name, ref, t_type))
                
        return entries

    def read_file_data(inode: dict) -> bytes:
        data_out = bytearray()
        
        file_offset = offset + inode["blocks_start"]
        for size_info in inode.get("block_sizes", []):
            is_uncompressed = bool(size_info & 0x1000000)
            c_size = size_info & 0xFFFFFF
            
            if c_size == 0:
                data_out.extend(b"\x00" * block_size)
                continue
                
            raw_block = data[file_offset:file_offset+c_size]
            file_offset += c_size
            
            if is_uncompressed:
                data_out.extend(raw_block)
            else:
                data_out.extend(_decompress_block(raw_block, compression))
                
        frag_idx = inode.get("fragment", 0xFFFFFFFF)
        if frag_idx != 0xFFFFFFFF:
            group = frag_idx // 512
            idx_in_group = frag_idx % 512
            
            ptr_offset = offset + fragment_table_start + group * 8
            ptr_bytes = data[ptr_offset:ptr_offset+8]
            meta_block_offset = struct.unpack(endian_fmt + "Q", ptr_bytes)[0]
            
            frag_entry_data = meta_reader.read_bytes(meta_block_offset, idx_in_group * 16, 16)
            f_start_block, f_size, f_unused = struct.unpack(endian_fmt + "QII", frag_entry_data)
            
            f_is_uncompressed = bool(f_size & 0x1000000)
            f_c_size = f_size & 0xFFFFFF
            
            f_raw = data[offset + f_start_block : offset + f_start_block + f_c_size]
            if f_is_uncompressed:
                f_block = f_raw
            else:
                f_block = _decompress_block(f_raw, compression)
                
            frag_offset = inode.get("frag_offset", 0)
            remaining = inode["file_size"] - len(data_out)
            data_out.extend(f_block[frag_offset:frag_offset+remaining])
            
        return bytes(data_out[:inode["file_size"]])

    extracted_files = []
    seen_inodes = set()
    
    def traverse(inode_ref: int, current_path: str):
        if inode_ref in seen_inodes:
            return
        seen_inodes.add(inode_ref)
        
        inode = read_inode(inode_ref)
        i_type = inode["type"]
        
        if i_type in (1, 8): # Directory
            entries = read_directory(inode["start_block"], inode["offset"], inode["file_size"])
            for name, child_ref, child_type in entries:
                if name in (".", ".."):
                    continue
                child_path = f"{current_path}/{name}" if current_path else name
                traverse(child_ref, child_path)
                
        elif i_type in (2, 9): # Regular file
            file_data = read_file_data(inode)
            file_abs_offset = offset + inode["blocks_start"]
            
            entry = FileSystemEntry(
                name=current_path,
                data=file_data,
                offset=file_abs_offset,
                size=inode["file_size"]
            )
            extracted_files.append(entry)

    traverse(root_inode, "")
    return info, extracted_files
