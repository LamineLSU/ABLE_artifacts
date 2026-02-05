rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B FF 55 E8 C8 FF FF FF ?? ?? ?? ?? FF 75 08 ?? }
        $pattern1 = { E8 C8 FF FF 59 FF 75 08 ?? FF 75 08 ?? FF 15 AC B0 41 00 ?? }
        $pattern2 = { 6A 40 53 E8 EC 00 00 00 ?? ?? ?? ?? 8B 4D FC ?? ?? }

    condition:
        any of them
}