rule EvasionBypass_Patterns {
    meta:
        description = "Evasion bypass rules targeting memory operations"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { FE DD A7 D4 CF 98 C3 FF ?? FF FF F8 B9 FF FF FF ?? }

    condition:
        any of them
}