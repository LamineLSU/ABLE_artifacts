rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 48 0C 74 12 8B 48 10 }
        $pattern1 = { 56 56 6A 35 6A 35 }
        $pattern2 = { 8B 55 14 8B 45 10 }

    condition:
        any of them
}