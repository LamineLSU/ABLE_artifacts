rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Push ebx + Call [address] (VM/Debugger check)
        $pattern1 = { 59 FF 15 ?? ?? ?? ?? }  // Pop ecx + Call [address] (Sandbox check)
        $pattern2 = { 50 FF 15 ?? ?? ?? ?? }  // Push eax + Call [address] (Analysis tool check)

    condition:
        any of them
}