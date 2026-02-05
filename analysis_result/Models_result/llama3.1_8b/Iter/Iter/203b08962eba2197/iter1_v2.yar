rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 83 E4 F8 83 EC 48 A1 64 66 45 }
        $pattern1 = { 3D 00 10 00 00 0F 82 }
        $pattern2 = { FF 15 ?? ?? ?? ?? E8 }

    condition:
        any of them
}