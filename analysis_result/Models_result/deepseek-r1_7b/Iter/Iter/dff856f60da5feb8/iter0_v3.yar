rule Bypass_Sample {
    meta:
        description = "Evasion bypass: skipped function call checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 FF ?? 8B 31 FF }  // Skips E9B5FCFFFF jump
        $pattern1 = { 8B 8F FF 0E 00 ?? 00 00 01 04 }  // Skips FF7508 push
        $pattern2 = { 8B E5 FF 03 FF ?? EB 03 }       // Skips E8F0 pop ebp
}

    condition: true
}