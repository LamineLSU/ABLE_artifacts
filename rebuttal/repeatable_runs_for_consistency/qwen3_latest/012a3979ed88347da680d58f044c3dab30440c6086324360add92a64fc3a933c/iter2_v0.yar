rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }  // Test + je + push (evasion check)
        $pattern1 = { B9 42 8C E7 00 50 E8 E3 FA FF FF }  // Function call setup (termination logic)
        $pattern2 = { 53 FF 15 2C A1 E7 00 }  // Push + ExitProcess call (direct API hook)

    condition:
        any of them
}