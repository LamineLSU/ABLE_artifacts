rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 06 8B 45 FC }  // Test + je + mov (evasion check)
        $pattern1 = { FF 15 ?? ?? ?? ?? }     // ExitProcess call (exit decision)
        $pattern2 = { 0F B6 54 04 90 89 C6 21 D6 09 C2 }  // Obfuscation logic (initial processing)

    condition:
        any of them
}