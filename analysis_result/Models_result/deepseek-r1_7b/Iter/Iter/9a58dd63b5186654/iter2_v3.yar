rule Bypass_Evasion_V1_0 {
    meta:
        description = "Evasion bypass for a malware checking system"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 8B 4D ?? ?? 6A ?? 5A 8B CE E8 ?? ?? 0F 84 ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 2F FC ?? 74 ?? }
        $pattern2 = { 8B 4D ?? ?? ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}