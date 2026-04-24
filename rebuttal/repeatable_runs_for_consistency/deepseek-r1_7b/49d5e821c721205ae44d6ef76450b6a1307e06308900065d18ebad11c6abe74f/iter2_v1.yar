rule Bypass_Sample_Evolved {
    meta:
        description = "Evasion bypass targeting exit decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B } // Target the test+je instruction at 0x617A-0x617C
        $pattern1 = { 3D 00 10 00 00 0F 82 } // Conditional jump before exit decision at 0x61E7-0x61E8
        $pattern2 = { 8B 45 FC 00 00 00 } // Final call dword ptr [003DA12Ch] leading to program exit

    condition:
        any of them
}