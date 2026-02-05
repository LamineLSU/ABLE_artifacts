rule Bypass_Sample
{
    meta:
        description = "Evasion bypass using multiple decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 7A ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 7A ?? ?? EC CA BE AD DE EE }
        $pattern1 = { E8 ?? ?? ?? ?? 0F 84 7A ?? 6A ?? 5A 8B CE E8 ?? ?? EC CA BE AD DE EE }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? EC CA BE AD DE EE }
    condition:
        any of them
}