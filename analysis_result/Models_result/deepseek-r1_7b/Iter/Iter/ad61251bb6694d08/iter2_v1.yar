rule Bypass_Evasion {
    meta:
        description = "Evasion bypass for function exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? 0F ?? ?? ?? ?? F2 0F 8E C9 FC ?? 0F 8A 85 C0 0F 84 ?? }
        $pattern1 = { E8 ?? 83 ?? 85 C0 0F 84 ?? ?? ?? ?? 75 8B CE 82 F1 FF 8E C9 FC 8A 85 C0 }
        $pattern2 = { 74 0A 0F 8E C9 FC 8A 85 C0 0F 84 ?? ?? ?? ?? 74 8B CE E8 ?? ?? ?? ?? F2 }

    condition:
        any of them
}