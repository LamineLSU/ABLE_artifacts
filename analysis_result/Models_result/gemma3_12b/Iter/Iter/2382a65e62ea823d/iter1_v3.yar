rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 B9 36 DF 35 55 }
        $pattern1 = { 6A 35 6A 00 51 50 }
        $pattern2 = { 56 56 50 50 E8 74 }

    condition:
        any of them
}