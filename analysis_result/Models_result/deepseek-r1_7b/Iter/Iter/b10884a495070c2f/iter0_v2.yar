rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting exit processes"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? 45 }
        $pattern1 = { FF 74 24 10 6A 00 FF 15 D8 90 AB 00 33 FF 53 FF 15 B8 90 AB 00 75 06 }
        $pattern2 = { ?? ?? 08 0E 45 ?? 04 ?? ?? 8B 45 ?? F3 A5 }

    condition:
        any of them
}