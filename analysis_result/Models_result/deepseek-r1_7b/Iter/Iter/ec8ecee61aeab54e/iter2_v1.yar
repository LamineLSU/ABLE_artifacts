rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific exit check points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 12 8B 4D F8 }  // CMP EAX,imm; JB based on result
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }  // TEST EAX; JE based on condition
        $pattern2 = { 6A 01 00 00 00 03 FF }  // Specific memory access patterns used for obfuscation
    condition:
        any of them
}