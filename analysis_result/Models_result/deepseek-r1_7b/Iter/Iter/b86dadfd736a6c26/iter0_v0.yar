rule Bypass_Sample {
    meta:
        description = "Bypassing anti-VM checks by targeting specific instruction points."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 54 B9 0A ?? ?? } // Targets the first call instruction and following mov
        $pattern1 = { E8 4F FF FF 6A 00 ?? } // Targets the second call instruction with surrounding context
        $pattern2 = { B9 0A 33 D2 F7 F1 ?? } // Targets the mov instruction with operand displacement

    condition:
        any of them
}