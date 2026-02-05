rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX + conditional jump (evasion check)
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }     // Push + ExitProcess call (exit decision)
        $pattern2 = { E8 4B 17 00 00 A1 88 85 17 01 }  // Call + memory read (obfuscation)

    condition:
        any of them
}