rule EvasionBypass {
    meta:
        description = "Evasion bypass patterns targeting memory pushes"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 40 5A 8B CE E8 ?? }  // 6 bytes
        $pattern1 = { 15 11 40 3F 7D C9 8E ?? ?? }  // 12 bytes (from trace 2)
        $pattern2 = { 6A 40 5A 8B CE E8 ?A ?C ?E ?? }  // 12 bytes
    condition:
        any of them
}