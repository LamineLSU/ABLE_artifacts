rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // test eax, eax + je (conditional jump)
        $pattern1 = { 33 FF FF 15 ?? ?? ?? ?? }   // xor edi, edi + call ExitProcess
        $pattern2 = { 8B 45 ?? FF 15 ?? ?? ?? ?? } // mov eax, [ebp+??] + call CloseHandle

    condition:
        any of them
}