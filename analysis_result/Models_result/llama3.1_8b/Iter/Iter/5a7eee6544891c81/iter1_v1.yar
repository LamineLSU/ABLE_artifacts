rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B E5 ?? 83 EC ?? 56 B9 ?? E8 ?? FF }
        $pattern1 = { 55 8B EC FF 75 08 E8 C1 FF FF FF 59 FF 15 5C C2 4C 00 }
        $pattern2 = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}