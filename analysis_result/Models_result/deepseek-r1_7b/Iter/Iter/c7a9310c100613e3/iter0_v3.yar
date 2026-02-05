rule Bypass_Sample {
    meta:
        description = "Evasion bypass rules for sandbox exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 37 5A E8 2A 7E 00 00 ?? ?? ?? ?? } // Around first target call
        $pattern1 = { E8 45 8B 45 C0 ?? ?? ?? ?? } // Different displacement pattern
        $pattern2 = { 6A 45 5A E8 2A 7E 00 00 ?? ?? ?? ?? } // Another specific call with wildcards

    condition:
        any of them
}