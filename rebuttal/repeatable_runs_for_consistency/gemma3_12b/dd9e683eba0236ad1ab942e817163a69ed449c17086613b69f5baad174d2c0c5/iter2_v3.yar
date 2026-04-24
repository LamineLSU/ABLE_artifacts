rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 10 8B 48 10 56 6A 35 6A 35 }
        $pattern1 = { 51 51 6A 00 6A 00 50 50 }
        $pattern2 = { E8 44 09 00 00 8B 55 14 8B 45 10 }

    condition:
        any of them
}