rule Bypass_Sample {
    meta:
        description = "Evasion bypass targeting exit decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"
    
    strings:
        $pattern0 = { 40 E7 C3 E8 8C FF FF } // Call to 0040E7C3h followed by displacement 0x8CFFFF
        $pattern1 = { FF B0 AC 75 0C ?? } // Call to 0040B0ACh with displacement and operand
        $pattern2 = { FF C8 FF FF FF 4D 8A ?? } // Call to dword ptr [ebp+08h] followed by other instructions
    
    condition:
        any of them
}