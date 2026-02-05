rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection for specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? }
        $pattern2 = { 74 0F 84 ?? ?? }

    condition:
        any of them
}