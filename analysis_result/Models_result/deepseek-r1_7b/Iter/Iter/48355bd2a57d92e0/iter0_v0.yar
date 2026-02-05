rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection rules targeting memory operand manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 C0 FF 75 BC E8 08 8D 02 00 }     // Push EB, call dword ptr [00B8A050h]
        $pattern1 = { C1 E8 08 A8 01 FF 75 08 8B 40 68 }   // Shr eax, 08h; test al, 01h; push dword ptr [ebp+08h]; call dword ptr [00B8A108h]
        $pattern2 = { 6A 03 FF 75 84 A8 01 75 10 FF 75 08 } // Push 0x03, call dword ptr [00B8A084h] (wildcard for address)
        
    condition:
        any of them
}