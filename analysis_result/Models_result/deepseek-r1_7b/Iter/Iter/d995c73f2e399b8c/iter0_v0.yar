rule EvasionBypass {
    meta:
        description = "Evasion bypass analysis for traced bytecode"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8E 8B 45 08 8B 45 10 C0 ?? ?? }
        $pattern1 = { 6A 35 6A 00 5A 8B CE 8D B0 74 0C ?? ?? }
        $pattern2 = { 56 56 56 5A 35 6A 00 00 ?? ?? }

    condition:
        any of them
}