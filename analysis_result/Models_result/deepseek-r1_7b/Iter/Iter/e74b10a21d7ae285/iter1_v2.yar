rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting conditional exit checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B 4F 5F }
        $pattern1 = { 83 F8 01 74 8B 4D F8 }
        $pattern2 = { 01 8C 3E 89 5D 00 00 }

    condition:
        (any of them)
}