rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 }
        $pattern1 = { 6A 35 6A 00 51 8D B0 98 0C 00 00 56 }
        $pattern2 = { 55 8B EC 8B 45 08 56 6A 36 51 8D B0 A0 0C 00 00 }

    condition:
        any of them
}