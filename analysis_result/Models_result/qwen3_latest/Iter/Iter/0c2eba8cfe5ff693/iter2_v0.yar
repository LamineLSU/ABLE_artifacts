rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 8D 95 F0 FE FF FF }  // test/je + push/lea sequence
        $pattern1 = { 83 7D FC 00 75 1B }                      // cmp/jne validation check
        $pattern2 = { FF 15 ?? ?? ?? ?? }                     // ExitProcess API call (wildcarded address)

    condition:
        any of them
}