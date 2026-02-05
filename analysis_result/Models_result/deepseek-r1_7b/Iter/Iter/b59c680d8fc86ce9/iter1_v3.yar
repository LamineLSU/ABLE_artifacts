rule Bypass_Sample_Evolved {
    meta:
        description = "Evasion bypass for sample using specific instruction sequences to target the decision point."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    
    strings:
        $pattern0 = { E8 F7 25 00 00 C1 E8 A8 01 }  // Call followed by shr test and je
        $pattern1 = { 55 8B EC E8 F7 25 00 00 C1 E8 A8 01 }  // Including mov ebp, esp before call
        $pattern2 = { E8 F7 25 00 00 55 8B EC E8 F7 25 00 00 C1 E8 A8 01 74 20 }  // Longer sequence with push and mov
    condition:
        any of the patterns match in the trace.
}