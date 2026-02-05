rule CorrectedRule
{
    meta:
        description = "Corrected YARA rule with valid patterns"
    strings:
        $pattern0 = { FF7508 E8 ?? ?? ?? ?? }
        $pattern1 = { FF7508 FF15 ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 59 }
    condition:
        any of them
}