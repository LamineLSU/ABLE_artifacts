rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 ?? ?? ?? ?? } // test eax, eax + je + call (evasion check)
        $pattern1 = { 33 DB 53 6A 40 53 68 40 11 9B 00 } // xor ebx, ebx + push sequence (evasion technique)
        $pattern2 = { FF 15 ?? ?? ?? ?? } // call to ExitProcess (exit decision point)

    condition:
        any of them
}