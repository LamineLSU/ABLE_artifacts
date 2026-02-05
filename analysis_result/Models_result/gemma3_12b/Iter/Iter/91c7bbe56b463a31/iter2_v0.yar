rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 68 18 93 42 00 68 02 00 00 80 FF 15 AC E0 42 00 }
        $pattern2 = { 8B 54 24 04 52 FF 15 EC E0 42 00 68 18 93 42 00 68 02 00 00 80 }

    condition:
        any of them
}