rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Push ebx + call to ExitProcess
        $pattern1 = { FF 75 08 E8 ?? ?? ?? ?? }  // Push ebp+08 + call to sandbox check
        $pattern2 = { 50 FF 15 ?? ?? ?? ?? }  // Push eax + call to sandbox check

    condition:
        any of them
}