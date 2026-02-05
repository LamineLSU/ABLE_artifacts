rule Bypass_Sample_Evasion {
    meta:
        description = "Evasion bypass detection using specific call instruction patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { FF 75 BC ?? 0F 84 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 8B 45 C4 8B ?? ?? ?? 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }

    condition:
        any of them
}