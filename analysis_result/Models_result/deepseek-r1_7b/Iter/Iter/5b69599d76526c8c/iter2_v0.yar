rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass detection using specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 45 }
        $pattern1 = { F7 45 13 E8 ?? 5E }
        $pattern2 = { 8B ?? ?? ?? ?? 8B EC }

    condition:
        any of them
}