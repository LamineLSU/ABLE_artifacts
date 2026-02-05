rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 FF 0F 84 ?? ?? ?? ?? 8B 45 C4 }
        $pattern1 = { 6A 03 ?? 5A 8B CE E8 ?? ?? ?? ?? FF 75 }
        $pattern2 = { FF 75 BC ?? FF 15 08 04 10 01 50 ?? }

    condition:
        any_of([$pattern0, $pattern1, $pattern2])
}