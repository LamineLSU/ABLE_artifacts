rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting exit decision points with specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { FF 15 F0 41 D1 00 3D 00 00 00 0F 82 }
        $pattern2 = { 6A 00 EE FF 15 F0 41 D1 00 }

    condition:
        any of them
}