rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 8B 85 F0 FE FF FF 8B CE E8 74 FA FF FF }
        $pattern2 = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}