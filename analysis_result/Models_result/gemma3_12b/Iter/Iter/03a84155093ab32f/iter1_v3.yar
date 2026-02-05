rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 35 6A 35 6A 00 }
        $pattern1 = { 56 56 6A 00 6A 00 }
        $pattern2 = { 8D B0 74 0C 00 00 56 }

    condition:
        any of them
}