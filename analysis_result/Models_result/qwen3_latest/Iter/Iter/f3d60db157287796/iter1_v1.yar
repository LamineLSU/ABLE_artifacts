rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 05 00 00 85 C0 0F 84 33 FD FF FF } // CALL TEST JE (evasion check)
        $pattern1 = { FF 15 2C A1 0E 01 } // ExitProcess call (exit decision)
        $pattern2 = { 8B 85 F0 FE FF FF 03 C3 BA 04 01 00 00 03 C1 E8 E3 FA FF FF } // Obfuscation sequence (evasion technique)

    condition:
        any of them
}