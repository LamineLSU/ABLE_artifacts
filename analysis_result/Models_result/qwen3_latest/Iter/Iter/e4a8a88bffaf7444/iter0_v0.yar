rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5A E8 ?? ?? ?? ?? }  // Pop edx + Call (sandbox check)
        $pattern1 = { 8B D0 E8 ?? ?? ?? ?? }  // Mov edx,eax + Call (sandbox check)
        $pattern2 = { 6A 00 E8 ?? ?? ?? ?? }  // Push 0 + Call (ExitProcess trigger)

    condition:
        any of them
}