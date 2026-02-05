rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 CD 3D 00 00 }
        $pattern1 = { 83 F8 01 74 20 64 A1 30 00 00 00 }
        $pattern2 = { 0F 01 D8 66 0F A7 44 }

    condition:
        any of them
}