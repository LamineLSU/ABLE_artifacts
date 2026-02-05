rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting stack canopies and memory checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }   // TEST EAX followed by conditional jump
        $pattern1 = { 6A 5B 5A 8B CE E8 25 05 00 ?? ?? ?? ?? 8D 95 F0 FE ?? }   // Modified call and test sequence
        $pattern2 = { 6A 40 FF 75 08 8B 40 E1 30 C3 ?? ?? ?? ?? FF 15 AC B0 41 00 }   // Dynamic jump based on AL register
}

    condition:
        any of them
}