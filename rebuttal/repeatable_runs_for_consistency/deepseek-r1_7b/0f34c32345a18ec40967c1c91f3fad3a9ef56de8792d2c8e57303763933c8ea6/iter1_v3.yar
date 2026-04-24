rule Evasion_Bypass {
    meta:
        description = "Evasion bypass for address checks in sandbox"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? } // Short jump to bypass a check
        $pattern1 = { E8 05 ?? } // Near jump with offset
        $pattern2 = { FC 8B ?? .? ?. ?? ?? } // Offset byte in memory access

    condition:
        any of them
}