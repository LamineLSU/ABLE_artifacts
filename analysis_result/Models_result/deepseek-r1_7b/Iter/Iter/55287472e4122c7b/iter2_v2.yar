rule Evasion_Bypass_Patterns
{
    meta:
        description = "Evasion bypass detection for multiple exit paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE ?? ?? ?? ?? }

    condition:
        any of them
}