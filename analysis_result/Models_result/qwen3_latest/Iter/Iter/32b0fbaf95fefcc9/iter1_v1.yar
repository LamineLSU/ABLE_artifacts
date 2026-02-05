rule Corrected_Rule
{
    meta:
        description = "Corrected YARA rule with patterns of at least 6 bytes"

    strings:
        $pattern0 = { 55 8B EC FF 75 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 59 }
        $pattern2 = { FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}