rule Bypass_Evasion {
    meta:
        description = "Evasion bypass for exit paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF 75 08 ?? ?? ?? ?? 45 ?? }  // Bypasses EAX test
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? FF FE }  // Skips call with wildcards
        $pattern2 = { 05 00 0F 75 04 00 ?? ?? ?? ?? 8B EC }  // Bypasses stack operations

    condition:
        any of them
}