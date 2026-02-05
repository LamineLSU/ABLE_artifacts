rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with more precise patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 74 12 }
        $pattern1 = { 3D 00 10 00 00 03 ?? ?? ?? ?? 5A B9 }
        $pattern2 = { E8 25 05 00 00 ?? ?? ?? ?? C3 }

    condition:
        any of them
}