"""Which characters are invisible, in one place for every check that needs to know.

Used by the engine (text a rule compares), the policy loader (rule values) and the
approval list (what a human is shown), so the three can never disagree.
"""

import unicodedata

# Unicode's Default_Ignorable_Code_Point property (DerivedCoreProperties.txt): software
# may draw nothing at all for these. Python's unicodedata doesn't have the property, and
# many of them are letters (Hangul fillers) or marks (variation selectors, U+034F), so
# the Cf/Cc categories miss them. Includes unassigned code points reserved for it.
DEFAULT_IGNORABLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD),  # soft hyphen
    (0x034F, 0x034F),  # combining grapheme joiner
    (0x061C, 0x061C),  # Arabic letter mark
    (0x115F, 0x1160),  # Hangul choseong / jungseong fillers
    (0x17B4, 0x17B5),  # Khmer inherent vowels
    (0x180B, 0x180F),  # Mongolian variation selectors, vowel separator
    (0x200B, 0x200F),  # zero-width space/joiners, direction marks
    (0x202A, 0x202E),  # direction embeddings and overrides
    (0x2060, 0x206F),  # word joiner, invisible operators, direction isolates
    (0x3164, 0x3164),  # Hangul filler
    (0xFE00, 0xFE0F),  # variation selectors (U+FE0F = "draw as emoji")
    (0xFEFF, 0xFEFF),  # byte order mark / zero-width no-break space
    (0xFFA0, 0xFFA0),  # half-width Hangul filler
    (0xFFF0, 0xFFF8),  # reserved
    (0x1BCA0, 0x1BCA3),  # shorthand format controls
    (0x1D173, 0x1D17A),  # musical format controls
    (0xE0000, 0xE0FFF),  # tags, variation selectors supplement, reserved
)


def is_invisible(ch: str) -> bool:
    """True for control, format and default-ignorable characters."""
    if unicodedata.category(ch) in {"Cf", "Cc"}:
        return True
    code = ord(ch)
    return any(first <= code <= last for first, last in DEFAULT_IGNORABLE_RANGES)
