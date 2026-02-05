rule Bypass_Sample
{
    meta:
        description = "Evasion bypass attempt at specific addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 ?? F8 E5 }  // Targeting first evasion point
        $pattern1 = { E8 ?? 8B CE E8 ?? F8 E5 }     // Targeting second evasion point
        $pattern2 = { 6A ?? 8B CE ?? ?? ?? 0F 84 ?? }  // Targeting third evasion point

    condition:
        any of them
}