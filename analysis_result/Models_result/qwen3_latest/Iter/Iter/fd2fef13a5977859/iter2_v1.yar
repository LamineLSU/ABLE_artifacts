rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F7 25 00 00 83 F8 01 74 20 }  // Call + cmp eax, 01h + je
        $pattern1 = { A8 01 75 10 }               // test al, 01h + jne
        $pattern2 = { FF 15 A0 F1 42 00 }            // ExitProcess call

    condition:
        any of them
}