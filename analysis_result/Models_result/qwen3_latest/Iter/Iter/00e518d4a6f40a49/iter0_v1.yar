rule MalwareEvasionBypass
{
    meta:
        description = "Detects evasion patterns in malware to prevent early exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-15"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX, JE to exit path
        $pattern1 = { 53 FF 15 ?? ?? ?? ?? }     // Push EBX, Call ExitProcess
        $pattern2 = { 83 C4 04 E8 ?? ?? ?? ?? }  // Add ESP, Call to evasion check

    condition:
        any of them
}