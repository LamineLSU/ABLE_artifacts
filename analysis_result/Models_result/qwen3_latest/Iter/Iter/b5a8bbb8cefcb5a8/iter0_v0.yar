rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0 bp1 bp2"

    strings:
        $pattern0 = { FF 75 08 E8 ?? ?? ?? ?? 59 }
        $pattern1 = { FF 75 08 FF 15 ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 59 }

    condition:
        any of them
}