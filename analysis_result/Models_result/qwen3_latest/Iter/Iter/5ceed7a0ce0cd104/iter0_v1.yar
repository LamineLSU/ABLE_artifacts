rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 FF 15 ?? ?? ?? ?? }  // push ebp+08h + call ExitProcess (4 bytes offset)
        $pattern1 = { A8 01 C1 E8 08 75 ?? }         // test al, 01h + shr eax, 08h + jne (1 byte offset)
        $pattern2 = { 50 FF 15 ?? ?? ?? ?? }        // push eax + call TerminateProcess (4 bytes offset)

    condition:
        any of them
}