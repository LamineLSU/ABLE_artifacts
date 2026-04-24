rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 83 EC 28 53 56 57 8B F1 8B D1 8D 4C 08 }
        $pattern1 = { 55 8B EC FF 75 08 E8 C1 FF FF FF 59 FF 75 08 FF 15 68 F3 20 00 }
        $pattern2 = { 55 8B EC FF 75 08 E8 C1 FF FF FF 59 FF 75 08 FF 15 68 F3 8D 00 }

    condition:
        any of them
}