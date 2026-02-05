rule Bypass_Evasion_Patterns {
    meta:
        description = "Bypass suspicious points in the binary by targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  // TEST EAX + JZ + MOV
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 0C 00 00 00 }  // POP/MOV instructions
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }  // PUSH/POP + CALL

    condition:
        any of them
}