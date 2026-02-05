rule Bypass_Evasion_3
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? }
        $pattern1 = { FF 15 AC B041 ?? 5A 8B CE E8 ?? ?? ?? ?? 8B 4D ??
        $pattern2 = { 6A ?? 5A 8B CE ?? ?? ?? ?? 8B C7 ??
    condition:
        any of them
}