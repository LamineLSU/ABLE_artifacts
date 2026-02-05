rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { E8 B1 25 02 00 83 C4 18 53 50 E8 B1 25 02 00 }
        $pattern2 = { 68 48 75 44 00 FF 15 00 40 44 00 8B F0 6A 08 56 FF 15 04 40 44 00 56 6A 00 8B F8 FF 15 70 41 44 00 }

    condition:
        any of them
}