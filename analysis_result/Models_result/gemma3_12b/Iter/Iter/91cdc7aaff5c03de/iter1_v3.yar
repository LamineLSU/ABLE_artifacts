rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 80 3D 86 0A 46 00 00 0F 85 C3 00 00 00 }
        $pattern1 = { 0F 84 26 05 00 00 }
        $pattern2 = { 38 1D 97 0A 46 00 75 F0 }

    condition:
        any of them
}