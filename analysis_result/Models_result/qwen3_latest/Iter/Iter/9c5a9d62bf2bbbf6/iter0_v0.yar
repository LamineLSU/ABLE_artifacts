rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // push ebx + call ExitProcess
        $pattern1 = { 85 C0 74 ?? ?? ?? ?? }  // test eax + je (sandbox check)
        $pattern2 = { B9 42 8C 08 00 50 E8 ?? ?? ?? ?? }  // mov ecx + push + call (resource cleanup)

    condition:
        any of them
}