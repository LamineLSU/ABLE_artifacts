rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - focuses on early conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B 4D FC }
        $pattern1 = { 5A 8B 45 FC 5A E8 25 05 00 00 }
        $pattern2 = { 33 DB BA 21 05 00 00 5F }
}

condition:
    any of them