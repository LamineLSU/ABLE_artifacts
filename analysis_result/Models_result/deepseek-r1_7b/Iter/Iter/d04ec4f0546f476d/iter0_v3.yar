rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 87 3D 00 ?? }
        $pattern1 = { CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any() {
            (any() &&
                skip 0) ||
            (any() &&
                skip 0) ||
            (any() &&
                skip 0)
        }
}