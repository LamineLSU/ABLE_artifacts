rule Bypass_Evasion {
    meta:
        description = "Detects stack-based bypass techniques used by malware"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC FF 75 08 ?? ?? 55 8B F4 ?? :? ? E8 C8 F? ?? ?: ?? ?? :? ?? ? FF 15 AC B0 41 00 }
        $pattern1 = { 8B EC FF 75 08 ?? ?? 55 8B F4 ?? :? ? E9 2A 8C 8F ?? ?? ?? ? FF 15 AC B0 41 00 }
        $pattern2 = { 8B EC FF 75 08 ?? ?? 55 8B F4 ?? :? ? E8 C8 F? ?? ?: ?? ?? :? ?? ? FF 15 AC B0 41 00 }

    condition:
        any of them
}