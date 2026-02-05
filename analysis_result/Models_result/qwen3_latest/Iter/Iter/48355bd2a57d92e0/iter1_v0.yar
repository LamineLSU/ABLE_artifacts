rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 FF 74 39 ?? ?? }  // Conditional check (test edi, edi + je)
        $pattern1 = { FF 15 84 A0 B8 00 }   // Direct call to ExitProcess
        $pattern2 = { 6A 03 FF 15 84 A0 B8 00 }  // Push + call to ExitProcess

    condition:
        any of them
}