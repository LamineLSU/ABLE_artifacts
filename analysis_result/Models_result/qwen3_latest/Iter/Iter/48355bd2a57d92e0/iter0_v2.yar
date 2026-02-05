rule Malware_Evasion_Sandbox_Detection
{
    meta:
        description = "Detects sandbox evasion techniques by identifying ExitProcess calls and related checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-05"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 6A 02 }  // ExitProcess call and following push
        $pattern1 = { E8 ?? ?? ?? ?? C3 }         // Call to 00B626B1 and ret instruction
        $pattern2 = { FF 15 ?? ?? ?? ?? 85 FF }   // WaitForMultipleObjects call and test edi

    condition:
        any of them
}