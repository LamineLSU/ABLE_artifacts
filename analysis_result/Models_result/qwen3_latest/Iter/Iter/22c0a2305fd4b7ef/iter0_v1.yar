rule MalwareEvasionBypass
{
    meta:
        description = "Detects malware evasion by early exit via ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "AI Assistant"
        date = "2023-10-15"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // PUSH EBX + CALL ExitProcess with displacement
        $pattern1 = { 85 C0 74 12 6A 5B }      // TEST EAX, EAX + JE + PUSH 0x5B
        $pattern2 = { 6A 5B 5A 8B CE E8 ?? ?? ?? ?? }  // PUSH 0x5B + POP EDX + MOV ECX, ESI + CALL with displacement

    condition:
        any of them
}