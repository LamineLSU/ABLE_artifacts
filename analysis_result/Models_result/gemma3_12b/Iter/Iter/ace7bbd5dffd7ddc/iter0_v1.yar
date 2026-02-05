rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 50 51 FF D2 5E 5D }
        $pattern1 = { 8D B0 98 0C 00 00 56 6A 35 6A 00 }
        $pattern2 = { 50 6A 35 6A 00 51 E8 74 0A }

    condition:
        any of them
}