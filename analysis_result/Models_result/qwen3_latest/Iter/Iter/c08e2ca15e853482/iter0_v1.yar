rule Malware_Evasion
{
    meta:
        description = "Detects evasion techniques involving ExitProcess and conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "AI Assistant"
        date = "2023-10-15"

    strings:
        $pattern0 = { 50 83 F8 11 74 ?? 0B C0 }  // CMP EAX, 11h + JE + OR EAX, EAX
        $pattern1 = { 85 C0 7F ?? E8 ?? ?? ?? }  // TEST EAX, EAX + JNE + CALL ExitProcess
        $pattern2 = { 7F ?? E8 ?? ?? ?? ?? }     // JNE + CALL ExitProcess

    condition:
        any of them
}