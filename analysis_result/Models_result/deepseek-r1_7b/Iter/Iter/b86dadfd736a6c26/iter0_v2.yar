rule Bypass_Pass2 {
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? EA EA EA DA CA }
        $pattern1 = { E8 ?? ?? ?? ?? 75 02 ?? EA EA EF AE BA EE CE }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? AE EA EF AB ED EE CE }

    condition:
        any of them
}