rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 6A 5B 5A 8B CE }  // Test + je + push + pop + mov
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }         // Push eax + call (offset wildcards)
        $pattern2 = { FF 75 08 E8 ?? ?? ?? ?? }      // Push dword + call (offset wildcards)

    condition:
        any of them
}