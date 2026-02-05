rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 11 74 05 8B }
        $pattern1 = { 83 F8 0C 74 2B 90 }
        $pattern2 = { 83 C4 0C 53 8A C9 }

    condition:
        any of them
}