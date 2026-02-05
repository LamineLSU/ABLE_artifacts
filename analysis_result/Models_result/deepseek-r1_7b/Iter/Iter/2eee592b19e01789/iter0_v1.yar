rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8A C5 A3 F7 FD FF ?? ?? ?? ?? 4C 6D } // Bypass sub rsp,20h
        $pattern1 = { DD 9E F7 7F E8 FE ?? > ?? ?? ?? ?? 6B BC } // Conditional jump bypass
        $pattern2 = { 5A C0 3F 4C FC 8D FF ?? ?? .? ?. ?? 6D 6A } // Function call bypass

    condition:
        any of them
}