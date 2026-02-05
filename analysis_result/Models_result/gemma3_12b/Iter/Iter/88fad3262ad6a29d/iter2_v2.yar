rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 16 E8 FD AF FF }
        $pattern1 = { 74 08 6A 00 FF 15 0C F2 47 00 }
        $pattern2 = { 3D 00 10 00 00 E8 76 E9 FF FF }

    condition:
        any of them
}