rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 D1 21 00 00 }
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 }
        $pattern2 = { FF 75 08 FF 15 B4 50 D2 00 }

    condition:
        any of them
}