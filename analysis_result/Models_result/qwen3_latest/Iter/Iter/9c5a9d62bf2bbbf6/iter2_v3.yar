rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8D 95 F0 FE FF FF }  // test eax, eax + je + lea
        $pattern1 = { FF 15 2C A1 08 00 }               // call ExitProcess
        $pattern2 = { 53 FF 15 2C A1 08 00 }            // push ebx + call ExitProcess

    condition:
        any of them
}