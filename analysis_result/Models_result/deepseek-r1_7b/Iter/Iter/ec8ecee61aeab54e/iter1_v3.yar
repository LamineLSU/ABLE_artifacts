rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 75 E8 ?? 6C 30 4F ?? ?? ?? ?? F4 7C }
        $pattern1 = { C9 0B 0E 00 00 05 8D 42 00 00 00 00 00 00 }  // EAX test with jump
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}