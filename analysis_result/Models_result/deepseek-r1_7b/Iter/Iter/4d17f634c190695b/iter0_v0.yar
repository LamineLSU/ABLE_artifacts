rule EvasionBypass {
    meta:
        description = "Evasion bypass rules targeting dword ptr [0045642Ch]"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 EC ?? ?? ?? ?? ?? ?? ?? ?? }
        $pattern1 = { 6A 5A 8B CE E8 ?? ?? ?? ?? 8B 45 EC ?? }
        $pattern2 = { EB 45 D8 ?? ?? ?? ?? ?? ?? ?? ?? 83 7D F8 }

    condition:
        any of them
}