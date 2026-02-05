rule Bypass_Evasion_3 {
    meta:
        description = "Bypass ExitProcess by skipping additional register manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 CE }  // Too short
        $pattern1 = { E8 CE }  // Also too short
        $pattern2 = { E8 CE }  // And this one is also too short

    condition:
        (any_of($pattern0, $pattern1, $pattern2))
}