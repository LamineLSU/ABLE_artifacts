rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 18 93 42 00 68 02 00 00 80 FF 15 AC E0 42 00 8B 4C 24 04 68 6C 8B 42 00 51 FF 15 88 E0 42 00 }
        $pattern1 = { 8B 35 78 30 42 68 00 93 42 00 FF D6 68 14 92 42 00 FF D6 68 E4 92 42 00 }
        $pattern2 = { 6A 00 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}