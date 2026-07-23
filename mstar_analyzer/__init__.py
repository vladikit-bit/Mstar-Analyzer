"""
MStar Firmware Analyzer

Modular firmware analysis framework for MStar/MediaTek based embedded devices.

The project is intended for reverse engineering firmware images,
recovering SDK information, detecting embedded resources,
identifying third-party libraries and documenting firmware internals.

Pipeline

    Firmware image
          │
          ▼
    Firmware map
          │
          ▼
    Entropy analysis
          │
          ▼
    Signature scan
          │
          ▼
    Recursive extraction
          │
          ▼
    String extraction
          │
          ▼
    Node classification
          │
          ├──────────────► Feature detection
          │
          ├──────────────► Library detection
          │                     │
          │                     ▼
          │              Library analyzers
          │
          ├──────────────► Embedded object detection
          │                     │
          │                     ▼
          │              Object analyzers
          │
          └──────────────► SDK / platform analysis
                                │
                                ▼
                          Final report

Architecture

Each analysis stage is isolated into its own module.

Detection modules identify candidate objects.

Analysis modules perform deep inspection.

Rendering modules are responsible only for presentation.

The framework is designed to be extensible by simply adding
new analyzers without modifying the analysis pipeline.
"""