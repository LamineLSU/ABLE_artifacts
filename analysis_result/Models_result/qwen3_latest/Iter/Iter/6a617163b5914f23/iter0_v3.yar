rule MalwareEvasionBypass
{
    meta:
        description = "Detects evasion checks and provides bypass patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-10"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // ExitProcess call with push ebx
        $pattern1 = { 6A 3C 8D 85 94 FE FF FF FF 15 ?? ?? ?? ?? }  // ShellExecuteEx call with surrounding setup
        $pattern2 = { 6A 3C E8 B1 25 02 00 }  // _memset call with preceding push

    condition:
        all of them
}