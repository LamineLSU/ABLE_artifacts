rule SandboxBypass
{
    meta:
        description = "Detects sandbox evasion by bypassing early exit checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-05"

    strings:
        $pattern0 = { 85 C0 74 ?? 6A 5B }  // Test + je + push (first check)
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test + je (second check)
        $pattern2 = { 53 FF 15 ?? ?? ?? ?? }  // Push + call to ExitProcess

    condition:
        any of them
}