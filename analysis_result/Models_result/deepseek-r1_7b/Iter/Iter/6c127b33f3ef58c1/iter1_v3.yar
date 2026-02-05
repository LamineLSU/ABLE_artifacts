rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 01 74 20 FF 75 08 FF 15 A0 }
        $pattern1 = { 8B EC 55 E8 F7 25 00 00 C1 E8 A8 01 75 10 FF 75 08 FF 15 3C F1 42 00 }
        $pattern2 = { 3D 00 10 00 00 00 00 0F 82 }
    condition:
        any of them
}