from __future__ import annotations

from dataclasses import dataclass, field

from .signatures import Finding
from .strings import StringFinding
from .firmware_map import FirmwareMap
from .detectors.features import Feature
from .detectors.objects import EmbeddedObject

@dataclass(slots=True)
class FirmwareNode:
    """
    Один вузол дерева firmware.

    Це може бути:

        flash.bin

        bootloader

        kernel.lzma

        kernel

        squashfs

        dtb

        ELF

        ...

    Будь-який вкладений об'єкт є таким самим FirmwareNode.
    """

    name: str

    offset: int

    data: bytes

    parent: FirmwareNode | None = None

    findings: list[Finding] = field(default_factory=list)

    strings: list[StringFinding] = field(default_factory=list)

    features: list[Feature] = field(default_factory=list)

    objects: list["EmbeddedObject"] = field(default_factory=list)
    
    firmware_map: FirmwareMap | None = None

    children: list["FirmwareNode"] = field(default_factory=list)

    metadata: dict[str, object] = field(default_factory=dict)

    node_type: str = "blob"

    format: str | None = None

    compression: str | None = None

    label: str | None = None

    analysis: dict[str, object] = field(default_factory=dict)

    code_caves: list[object] = field(default_factory=list)

    @property
    def title(self):
        """
        Human-readable node name.
        """

        if self.label:
            return self.label

        if self.format:
           if self.offset is not None:
                return f"{self.format}@0x{self.offset:08X}"
           return self.format

        return self.name

    # ---------------------------------------------------------

    @property
    def size(self) -> int:
        return len(self.data)

    # ---------------------------------------------------------

    @property
    def depth(self) -> int:

        depth = 0

        node = self.parent

        while node is not None:

            depth += 1

            node = node.parent

        return depth

    # ---------------------------------------------------------

    @property
    def path(self) -> str:

        parts = []

        node: FirmwareNode | None = self

        while node is not None:

            parts.append(node.name)

            node = node.parent

        return "/".join(reversed(parts))

    # ---------------------------------------------------------

    @property
    def display_path(self) -> str:
        """
        Те саме, що `path`, але з `title` замість сирого `name`.

        `name` — це завжди метод екстракції ("lzma-alone", "gzip", ...),
        тож два різні вузли (напр. Bootloader і Streaming Engine, обидва
        видобуті через LZMA) матимуть ІДЕНТИЧНИЙ `path`. `title` враховує
        семантичну класифікацію (classify_node) і різнить їх.
        """

        parts = []

        node: FirmwareNode | None = self

        while node is not None:

            parts.append(node.title)

            node = node.parent

        return " / ".join(reversed(parts))

    # ---------------------------------------------------------

    def add_child(self, child: "FirmwareNode") -> None:

        child.parent = self

        self.children.append(child)

    # ---------------------------------------------------------

    def walk(self):

        yield self

        for child in self.children:

            yield from child.walk()

    # ---------------------------------------------------------

    def pretty(self, indent: str = "") -> str:

        parts = [f"{indent}{self.title}"]

        if self.compression:
            parts.append(f"[{self.compression}]")

        if self.node_type != "blob":
            parts.append(f"<{self.node_type}>")

        parts.append(f"({self.size:,} bytes)")

        line = " ".join(parts)

        lines = [line]

        for child in self.children:
            lines.append(
               child.pretty(indent + "    ")
            )

        return "\n".join(lines)