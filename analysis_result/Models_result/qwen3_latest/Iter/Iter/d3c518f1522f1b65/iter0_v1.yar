rule SandboxEvasionDetection
{
    meta:
        description = "Detects sandbox evasion by identifying early exit patterns in malware execution flow."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "CyberDefense Analyst"
        date = "2023-10-05"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX/EAX + JE conditional check
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }     // Push EAX + Call CloseHandle
        $pattern2 = { 53 FF 15 ?? ?? ?? ?? }     // Push EBX + Call ExitProcess

    condition:
        any of them
}