rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 FF 15 ?? ?? ?? ?? }  // PUSH 0x0 + CALL ExitProcess
        $pattern1 = { 56 FF 15 ?? ?? ?? ?? 74 03 }  // PUSH ESI + CALL OpenEventA + JZ
        $pattern2 = { 57 57 57 FF 15 ?? ?? ?? ?? }  // 3x PUSH EDI + CALL CreateEventA

    condition:
        any of them
}