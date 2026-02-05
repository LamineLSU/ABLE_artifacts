rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific exit checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 ?? ?? ?? ?? 55 }
        $pattern1 = { E8 CD 3D 00 00 74 20 ?? ?? ?? 9B 65 5A ?? }
        $pattern2 = { CB FF 04 83 F8 01 ?? ?? ?? 13 65 6D }
}

condition:
    (any of them)