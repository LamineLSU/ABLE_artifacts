rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }  // test eax, eax + je + push
        $pattern1 = { FF 15 2C A1 01 01 }  // call to ExitProcess
        $pattern2 = { 6A 5B 5A 68 0D 00 00 00 }  // push/pop + push 0x0D

    condition:
        any of them
}