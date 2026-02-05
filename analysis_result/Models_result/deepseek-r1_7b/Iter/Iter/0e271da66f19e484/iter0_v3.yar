rule Bypass_Sample {
    meta:
        description = "Evasion bypass for ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 01 16 61 7A EA 01 16 61 7C ?? }
        $pattern1 = { 01 38 61 7A EA 01 38 61 7E ?? }
        $pattern2 = { 00 40 E7 F3 EA 00 40 E7 FB ?? }

    condition:
        any of them
}