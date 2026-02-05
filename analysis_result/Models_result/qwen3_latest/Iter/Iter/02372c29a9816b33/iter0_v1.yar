rule Malware_Evasion_Bypass
{
    meta:
        description = "Detects evasion bypass patterns in malware that terminates early in sandbox/VM environments."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "AI Assistant"
        date = "2023-10-15"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX, EAX followed by JE (evasion check)
        $pattern1 = { A1 88 85 EC 00 85 C0 }      // MOV EAX, [00EC8588h] followed by Test EAX, EAX
        $pattern2 = { 50 E8 ?? ?? ?? ?? }         // PUSH EBX followed by CALL to ExitProcess (exit path)

    condition:
        any of them
}