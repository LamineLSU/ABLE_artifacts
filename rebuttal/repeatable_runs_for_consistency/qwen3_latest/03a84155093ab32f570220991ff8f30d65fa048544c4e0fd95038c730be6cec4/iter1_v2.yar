rule ExitProcess_Bypass
{
    meta:
        description = "Detects evasion by calling ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-01"

    strings:
        $pattern0 = { 50 E8 ?? ?? ?? ?? }  // push eax + call (offset wildcard)
        $pattern1 = { 83 C4 ?? 52 FF D0 }   // add esp + push edx + call
        $pattern2 = { E8 ?? ?? ?? ?? 83 C4 ?? }  // call + add esp (wildcard offset)

    condition:
        any of ($pattern0, $pattern1, $pattern2)
}