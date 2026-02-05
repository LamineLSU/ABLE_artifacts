rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 55 8B EC FF 75 08 }  // Initial push ebp and call
        $pattern1 = { FF 75 08 ?? ?? ?? ?? }  // Displacement and call with wildcards
        $pattern2 = { 6A 5A 8B CE E8 FF 45 ?? }    // Alternative instruction sequence leading to the call

    condition:
        any()
}