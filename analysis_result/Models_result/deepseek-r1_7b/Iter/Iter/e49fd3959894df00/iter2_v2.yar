rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific calls with offsets"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 }
        $pattern2 = { FC CD 85 C9 EC EC FF 15 44 74 44 00 CA DD 00 44 74 44 }

    condition:
        any of them
}