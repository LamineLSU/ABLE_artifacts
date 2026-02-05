rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with multiple early bypass attempts"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 5C 85 C0 74 12 }
        $pattern1 = { 8E 7F 83 F8 01 74 12 8B }
        $pattern2 = { 8A 0B 53 C9 75 0C }

    condition:
        (any of them match)
}