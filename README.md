# Surface SAM firmware tools

These tools can be used to unpack and modify the firmware running on the SAM EC, which is used in many MS Surface devices.

## WARNING: Do NOT try to modify the firmware on your Surface device unless you really know what you're doing! I am not responsible if you brick your device!

## `sam-fw-unpack.py`

Extracts firmware images from a `SurfaceSAM_*.bin` firmware package.

## `sam-fw-upload.py`

Upload a firmware image to the SAM.
Requires the `surface_aggregator_cdev` module and `libssam.py` from: https://github.com/linux-surface/surface-aggregator-module
After uploading new firmware, the SAM must be reset to activate it. You can do this by holding the power and volume up buttons for 15 seconds (this will turn off the Surface).

## `sam-fw-crc16.py`

Update firmware image CRC. Can be used after manually modifying a firmware image.

## `sam-fw-patch.py`

Patch firmware using patch file (also updates CRC).

