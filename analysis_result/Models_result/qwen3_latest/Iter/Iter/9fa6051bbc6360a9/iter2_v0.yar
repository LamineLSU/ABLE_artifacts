rule ExitProcess_Evasion
{
    meta:
        description = "Detects potential evasion or hooking around ExitProcess call"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-25"
    
    strings:
        $pattern0 = { 83 C4 ?? 8B 06 FF D0 }
        $pattern1 = { 50 E8 ?? ?? ?? ?? 8B 55 ?? }
        $pattern2 = { 8B 88 ?? ?? ?? ?? }

    condition:
        any of them
}