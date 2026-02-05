rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 33 FF 8B C7 FF 15 ?? ?? ?? ?? }  // xor edi, edi + mov eax, edi + call ExitProcess
        $pattern1 = { 74 07 50 FF 15 ?? ?? ?? ?? }      // je 0x07 + push eax + call CloseHandle
        $pattern2 = { 85 C0 74 12 6A 5B }               // test eax, eax + je 0x12 + push 0x5B

    condition:
        any of them
}