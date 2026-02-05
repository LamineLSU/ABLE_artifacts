rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules for specific address"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 E8 ?? ?? ?? ?? }
        $pattern1 = { 74 75 0F 84 ?? ?? ?? ?? 8B 45 ?? }  // Fixed "??3D" to make it real
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }

    condition:
        any of them
}