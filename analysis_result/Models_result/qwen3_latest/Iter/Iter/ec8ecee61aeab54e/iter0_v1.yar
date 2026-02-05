rule SandboxBypass
{
    meta:
        description = "Malware evasion bypass via conditional checks and function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "RedTeam"
    
    strings:
        $pattern0 = { 59 59 84 C0 74 2A } // test al, al and je to exit
        $pattern1 = { 83 F8 20 53 FF 15 ?? ?? ?? ?? } // cmp eax, 20h and call ExitProcess
        $pattern2 = { 53 FF 15 ?? ?? ?? ?? } // push ebx and call ShellExecuteW
    
    condition:
        any of them
}