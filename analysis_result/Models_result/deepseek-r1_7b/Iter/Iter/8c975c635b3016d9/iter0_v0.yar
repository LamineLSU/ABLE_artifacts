rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A 5B 5A 8B CE E8 FF ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 64 A1 30 8B 40 68 C1 E8 A8 75 ?? FF ?? ?? 59 FF }

    condition:
        any of them
}