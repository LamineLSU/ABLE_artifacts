rule MalwareEvasion
{
    meta:
        description = "Detects evasion techniques in malware through specific function calls and checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "AI Assistant"
        date = "2023-10-15"

    strings:
        $pattern0 = { 68 D8 40 46 00 6A 00 FF 15 ?? ?? ?? ?? 83 F8 20 }  // ShellExecuteW call and EAX comparison
        $pattern1 = { FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 3D B7 00 00 00 }  // CreateMutexA + GetLastError + error check
        $pattern2 = { FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // CloseHandle call with prior memory write

    condition:
        any of them
}