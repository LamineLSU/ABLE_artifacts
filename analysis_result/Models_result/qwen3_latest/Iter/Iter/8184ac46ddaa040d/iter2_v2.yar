rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }  // test+je+push sequence
        $pattern1 = { 33 C9 E8 4B 17 00 00 }  // xor+call to obfuscated function
        $pattern2 = { A1 88 85 C7 00 85 C0 74 07 }  // mov+test+je before ExitProcess

    condition:
        any of them
}