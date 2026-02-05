rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 6A ?? }  // test eax, eax + je + push
        $pattern1 = { 53 FF 15 ?? ?? ?? ?? }  // push ebx + call ExitProcess
        $pattern2 = { 85 C0 74 07 50 8B 45 ?? }  // test eax, eax + je + push + mov

    condition:
        any of them
}