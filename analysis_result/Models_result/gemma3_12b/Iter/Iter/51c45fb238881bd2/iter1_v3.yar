rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 85 ?? ?? ?? ?? }
        $pattern1 = { FF 96 B0 00 00 00 }
        $pattern2 = { 83 3D 00 10 49 00 00 }

    condition:
        any of them
}