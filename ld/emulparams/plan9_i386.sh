SCRIPT_NAME=plan9
OUTPUT_FORMAT="plan9-i386"
TARGET_PAGE_SIZE=0x1000
TEXT_START_ADDR=0x1020
ARCH=i386
ENTRY=_main
# Plan 9 data starts immediately after text (no page-alignment gap).
# The default DATA_ALIGNMENT=ALIGN(SEGMENT_SIZE)=ALIGN(0x1000) would
# page-pad the data section, making symbol VMAs differ from what the
# Plan 9 kernel maps at runtime (TEXTADDR + a_text = 0x1020 + text_size).
# Use ALIGN(4) so data is placed contiguously after text with only
# C-required struct alignment, matching native Plan 9 8l layout.
DATA_ALIGNMENT="ALIGN(4)"
