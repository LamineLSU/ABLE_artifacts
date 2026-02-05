rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"
    
    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF } // This is a placeholder; ensure it's replaced with wildcarded pattern
        $pattern1 = { E8 C8 FF FF FF 59 FF 75 08 ?? ?? }
        $pattern2 = { 8B 45 ?? ?? ?? ?? }

    condition:
        any of them
}