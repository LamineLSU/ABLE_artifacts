rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 37 5A E8 2A 7E 00 00 }
        $pattern1 = { 66 83 F8 01 75 20 }
        $pattern2 = { 66 83 F8 01 75 0D }

    condition:
        any of them
}