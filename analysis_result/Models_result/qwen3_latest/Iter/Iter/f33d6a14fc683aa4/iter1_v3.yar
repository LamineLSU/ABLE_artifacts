rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? } // CALL → TEST EAX → JE
        $pattern1 = { FF 15 ?? ?? ?? ?? } // ExitProcess call
        $pattern2 = { 33 DB BA 21 05 00 00 53 6A 40 53 68 40 11 A3 00 } // XOR + mov + push sequence

    condition:
        any of them
}