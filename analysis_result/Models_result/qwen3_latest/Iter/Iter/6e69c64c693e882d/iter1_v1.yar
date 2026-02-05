rule CorrectedRule
{
    meta:
        description = "Corrected YARA rule with properly formatted patterns"
    strings:
        $pattern0 = { 55 8B EC FF 75 08 }
        $pattern1 = { 8B EC E8 ?? ?? ?? ?? }
        $pattern2 = { FF 75 08 FF 15 ?? ?? ?? ?? }
    condition:
        any of them
}