rule Bypass_Sample {
    meta:
        description = "Evasion bypass targeting specific jumps and conditionals"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=Skip,count=0"

    strings:
        $pattern0 = { E8 F7 C1 E8 A8 01 } // Around shr eax and jne
        $pattern1 = { 64 A3 5A ?? ?? ?? } // Displacement jump with wildcards
        $pattern2 = { 8B 45 E8 F7 C1 E8 A8 01 }

    condition:
        any of them
}