rule EvasionCheck
{
    meta:
        description = "Detects sandbox evasion checks and exit calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-15"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? }  // Call to ExitProcess
        $pattern1 = { 8B 0D ?? ?? ?? ?? 85 C0 75 ?? }  // mov ecx, test eax, jne
        $pattern2 = { E8 ?? ?? ?? ?? 8B D0 }  // Call to function, mov edx

    condition:
        any of them
}