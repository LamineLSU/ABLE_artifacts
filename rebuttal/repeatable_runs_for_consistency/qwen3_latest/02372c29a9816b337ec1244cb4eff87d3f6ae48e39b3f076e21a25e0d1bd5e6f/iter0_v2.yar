rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Push ebx + call ExitProcess
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }  // Push eax + call CloseHandle
        $pattern2 = { 68 40 11 EC 00 E8 ?? ?? ?? ?? }  // Push 00EC1140h + call 00EC44B9h

    condition:
        any of them
}