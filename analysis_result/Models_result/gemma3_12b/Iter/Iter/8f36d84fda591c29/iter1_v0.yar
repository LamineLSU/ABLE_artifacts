rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 51 50 51 8D B0 A0 0A 00 00 }
        $pattern1 = { 56 50 8D B0 A8 0A 00 00 }
        $pattern2 = { 56 6A 36 6A 00 51 8D B0 A8 0A 00 00 }

    condition:
        any of them
}