rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 83 E4 F0 33 C9 B9 ?? ?? ?? ?? }
        $pattern1 = { 8B 05 ?? ?? ?? ?? 8B 50 08 85 C0 74 13 }
        $pattern2 = { 3D 00 10 00 00 0F 82 20 00 00 }

    condition:
        any of them
}