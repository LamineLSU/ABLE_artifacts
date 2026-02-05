rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with more specific patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? FF 15 50 44 00 }
        $pattern1 = { 3D 00 10 00 00 0F 82 }
        $pattern2 = { FC F8 1A 7C 00 00 00 00 5E 64 }

    condition:
        any of them
}