rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule targeting conditional jumps before execution"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC FF7508 C8FF E8C8FFFF ???? } // 6 instructions (12 bytes)
        $pattern1 = { FF7508C8F8BEC FF15ACB04100 ???? } // Sequence after first call
        $pattern2 = { ?? 8B EC FF7508C8F8BEC ?? } // Distinct bypass attempt elsewhere

    condition:
        any of them
}