rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern1 = { E5 08 E1 7D 63 F6 F6 19 0A }
        $pattern2 = { 56 6A 35 6A 00 51 8D B0 74 0C 00 00 56 50 E8 44 09 00 00 }

    condition:
        any of them
}