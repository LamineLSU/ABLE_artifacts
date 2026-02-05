rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific early conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B 45 FC }
        $pattern1 = { 3D 00 10 00 00 00 0F 82 }
        $pattern2 = { A1 FF 75 69 E1 EC 00 00 }  // Example distinct pattern

    condition:
        any of them
}