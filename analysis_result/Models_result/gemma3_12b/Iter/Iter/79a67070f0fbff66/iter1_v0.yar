rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 3D 5C 42 61 00 00 }
        $pattern1 = { 8B 55 E4 52 E8 5F 88 00 00 }
        $pattern2 = { 8B 45 C4 83 C0 01 89 45 C4 }

    condition:
        any of them
}