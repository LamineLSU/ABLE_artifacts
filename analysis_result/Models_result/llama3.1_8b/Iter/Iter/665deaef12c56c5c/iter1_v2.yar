rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 8B FF 55 8B EC E8 C8 FF FF FF }
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 }
        $pattern3 = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}