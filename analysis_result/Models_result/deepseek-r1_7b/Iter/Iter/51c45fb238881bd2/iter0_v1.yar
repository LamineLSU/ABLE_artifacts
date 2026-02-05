rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass using conditional jumps and stack checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 33 C0 F9 75 0E 8B 75 0E ?? ?? ?? 45 83 0F FF ?? ?? ?? 6B 8B ?? 1C ?? }

    condition:
        any of them
}