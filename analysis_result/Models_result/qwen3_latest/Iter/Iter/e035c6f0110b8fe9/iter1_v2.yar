rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B CE E8 25 05 00 00 }  // First evasion check (test+je + call)
        $pattern1 = { 85 C0 0F 84 33 FD FF FF }           // Second evasion check (test+je)
        $pattern2 = { FF 15 2C A1 2F 00 }               // ExitProcess call (direct exit decision)

    condition:
        any of them
}