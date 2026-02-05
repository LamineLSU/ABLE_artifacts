rule EvasionBypass {
    meta:
        description = "Evasion bypass using register manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? 5A 8B CE E8 ?? ?? ?? ?? FF C1 ?? }
        $pattern1 = { 6A 5B 5A ?? ?? ?? 0F 84 74 12 ?? ?? ?? ?? FF C1 ?? }
        $pattern2 = { ?? ?? ?? ?? 8B EC 5A 0F 84 74 12 ?? ?? ?? ?? FF C1 ?? }

    condition:
        any of them
}