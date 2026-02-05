rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 06 83 C4 14 52 8B 16 50 }
        $pattern1 = { 52 8B 16 50 51 8D B0 98 0C 00 00 }
        $pattern2 = { 52 8B 16 50 51 6A 35 6A 00 }

    condition:
        any of them
}