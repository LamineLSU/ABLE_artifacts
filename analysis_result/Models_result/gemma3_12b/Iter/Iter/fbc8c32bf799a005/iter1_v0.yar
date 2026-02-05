rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 81 D1 47 66 C7 44 24 24 00 00 C6 44 24 26 00 }
        $pattern1 = { 81 D1 89 6A 05 6A 00 50 68 50 80 85 00 51 6A 00 FF 15 C8 81 85 00 }
        $pattern2 = { 81 D1 B1 E8 D6 39 00 00 E8 B1 28 00 00 }

    condition:
        any of them
}