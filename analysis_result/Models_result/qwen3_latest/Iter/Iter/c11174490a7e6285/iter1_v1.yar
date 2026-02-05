rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A }  // Early test/je + push/pop sequence
        $pattern1 = { FF 15 88 A0 C2 00 FF 15 2C A1 C2 00 }  // CloseHandle + ExitProcess calls
        $pattern2 = { B9 42 8C C2 00 50 E8 E3 FA FF FF }  // Unique calculation + call sequence

    condition:
        any of them
}