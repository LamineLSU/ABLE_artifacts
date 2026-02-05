rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }  // Test EAX + JE + PUSH (sandbox check)
        $pattern1 = { 33 FF FF 15 ?? ?? ?? ?? 8B C7 }  // XOR EBX + CALL ExitProcess + MOV EAX (termination)
        $pattern2 = { 50 FF 15 ?? ?? ?? ?? 53 }  // PUSH EAX + CALL CloseHandle + PUSH EBX (handle check)

    condition:
        any of them
}