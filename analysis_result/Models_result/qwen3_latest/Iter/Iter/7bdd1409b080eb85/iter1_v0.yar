rule EvasionPatterns
{
    meta:
        description = "Detects evasion patterns involving GetModuleHandleA, GetProcAddress, and ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    strings:
        $pattern0 = { 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? }
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? }
        $pattern2 = { FF 74 24 04 FF D0 FF 15 ?? ?? ?? ?? }
    condition:
        any of them
}