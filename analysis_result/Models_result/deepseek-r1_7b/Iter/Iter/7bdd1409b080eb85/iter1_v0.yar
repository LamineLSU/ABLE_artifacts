rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specialized points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 1C 27 47 0F 85 C0 74 16 }
        $pattern1 = { 68 0C 27 47 0F 85 C0 74 16 }
        $pattern2 = { 68 1C 27 47 0F 85 C0 FF 15 8C 62 }

    condition:
        any of them
}