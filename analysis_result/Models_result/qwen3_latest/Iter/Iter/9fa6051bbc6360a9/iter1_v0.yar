rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6F 77 B8 0A 04 B6 }
        $pattern1 = { 8D B0 74 0C 00 00 }
        $pattern2 = { E8 44 09 00 00 8B 55 14 8B 45 10 }

    condition:
        any of them
}