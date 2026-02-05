rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 6A 5B 5A }  // test eax, eax + je + push + pop
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? }  // test eax, eax + je with offset + lea
        $pattern2 = { 53 FF 15 ?? ?? ?? ?? }  // push ebx + call to ExitProcess

    condition:
        any of them
}