rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 35 6A 00 51 51 }
        $pattern1 = { 8D B0 98 0C 00 00 56 56 50 50 }
        $pattern2 = { E8 74 0A 00 00 8B 55 14 }

    condition:
        any of them
}