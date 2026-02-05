rule Bypass_Sample {
    meta:
        description = "Bypass Evasion through multiple instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 56 EA E8 F8 5E }
        $pattern1 = { 74 0F 8B CE E8 FF }
        $pattern2 = { 56 56 EA E8 FF D2 5E }

    condition:
        any of them
}