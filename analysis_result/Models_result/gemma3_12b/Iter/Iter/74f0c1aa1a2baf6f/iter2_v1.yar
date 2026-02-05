rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3C 22 75 28 41 8A 11 }
        $pattern1 = { 3C 22 74 11 8A C2 84 D2 }
        $pattern2 = { 5D 15 0F 45 C1 EB 0E }

    condition:
        any of them
}