rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8D 95 F0 FE FF FF } // test+je+lea (evasion check)
        $pattern1 = { FF 15 2C A1 A3 00 } // ExitProcess call (direct evasion indicator)
        $pattern2 = { 6A 5B 5A 8B CE E8 ?? ?? ?? ?? } // push/pop+mov+call (obfuscated control flow)

    condition:
        any of them
}