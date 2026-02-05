rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 45 7C ?? ?? ?? ?? 5B F7 1E ?? }
        $pattern1 = { 74 9A ?? ?? ?? ?? }
        $pattern2 = { 6D A3 ?? ?? ?? ?? }

    condition:
        any of them
}