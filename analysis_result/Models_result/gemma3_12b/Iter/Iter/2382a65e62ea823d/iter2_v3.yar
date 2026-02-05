rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 B9 36 DF 35 55 }
        $pattern1 = { 8B 45 08 8B 48 14 56 6A 35 }
        $pattern2 = { 51 50 51 50 E8 74 0A 00 00 }

    condition:
        any of them
}