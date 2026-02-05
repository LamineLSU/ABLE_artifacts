rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 84 24 18 03 00 00 50 57 68 68 42 FB 00 }
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 }
        $pattern2 = { FF 15 98 30 FB 00 5F 5E 5D 5B 81 C4 CC B3 00 00 }

    condition:
        any of them
}