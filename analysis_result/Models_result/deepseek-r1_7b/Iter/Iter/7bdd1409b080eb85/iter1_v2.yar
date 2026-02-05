rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 60 85 70 C0 90 74 10 16 12 8B 13 45 14 FC },
        $pattern1 = { 16 85 17 C0 19 74 20 16 22 8B 23 45 24 FC },
        $pattern2 = { 32 85 33 C0 35 74 36 16 38 8B 39 45 40 FC }

    condition:
        (matching any of the patterns)
}