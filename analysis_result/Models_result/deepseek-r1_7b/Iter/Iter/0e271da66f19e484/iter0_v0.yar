rule Bypass_Evasion_001 {
    meta:
        description = "Evasion bypass using conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 FF 82 50 50 00 0F 84 33 FD FF FF 8D 95 F0 FE FF FF FF 8B 5A 00 00 }  // Conditional jump to evil address
        $pattern1 = { 6A 5B 8B CE E8 25 05 00 00 0F 84 33 FD FF FF 74 07 C3 FF 8B 85 F0 FE FF FF 53 53 }  // Memory access and conditional jump
        $pattern2 = { 8B EC FF 75 08 E8 C8 FF FF FF 74 07 C3 FF 8B E5 F0 FE FF FF 53 FF 5E }  // Jmp to evil address with offset
}

    condition:
        any of them
}