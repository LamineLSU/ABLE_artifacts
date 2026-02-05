rule Bypass_Sample {
    meta:
        description = "Evasion bypass rules targeting attacker check mechanisms"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 C0 8B E8 FF FF ?? }  // Combines push ebp and call with displacement
        $pattern1 = { FF C0 E8 C8 FF FF ?? }   // Captures another check from the second trace
        $pattern2 = { 59 FF 75 08 FF 75 08 ?? }  // Uses wildcards for context

    condition:
        any of them
}