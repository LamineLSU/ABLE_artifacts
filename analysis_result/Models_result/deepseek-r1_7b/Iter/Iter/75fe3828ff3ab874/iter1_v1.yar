rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting conditional exit checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4D FC EC DD EB 04 }
        $pattern1 = { 74 12 00 08 61 90 }
        $pattern2 = { 83 F8 01 EA 00 00 00 01 F8 }
}

condition:
    (any of ($pattern0, $pattern1, $pattern2))