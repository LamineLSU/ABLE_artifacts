rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 74 03 }
        $pattern1 = { E8 ?? ?? ?? ?? 75 01 }
        $pattern2 = { E8 A9 01 00 00 50 74 03 }

    condition:
        any of them
}