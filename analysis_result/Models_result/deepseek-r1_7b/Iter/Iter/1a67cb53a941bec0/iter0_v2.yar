rule BypassProcessEscape {
    meta:
        description = "Evasion bypass detection"
        capability = "process_evasion"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 8B 40 53 FF ?? }
        $pattern1 = { E8 CE E8 C8 FF FF } // Example from another trace
        $pattern2 = { 6A 5B 8B 40 53 FF C7 ?? }

    condition:
        any of them
}