rule Bypass_Evasion_Patterns {
    meta:
        description = "Detection of Evasion bypass techniques in malware"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 75 ?? 0C ?? ?? ?? ?? 0F 84 8A 00 00 00 }
        $pattern2 = { 8B 45 FC ?? ?? ?? ?? ?? ?? }  // Example for third pattern
    condition:
        any of them
}