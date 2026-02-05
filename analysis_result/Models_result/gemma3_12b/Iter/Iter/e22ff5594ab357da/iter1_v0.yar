rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 20 00 D1 B7 90 }
        $pattern1 = { 64 A1 30 00 00 00 EA DD 00 00 00 30 }
        $pattern2 = { FF 15 B4 50 D2 00 CA DD 00 D2 50 B4 }

    condition:
        any of them
}