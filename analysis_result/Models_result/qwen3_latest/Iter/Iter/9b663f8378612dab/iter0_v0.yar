rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Push ebx + Call ExitProcess
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }  // Push eax + Call CloseHandle
        $pattern2 = { 33 C9 E8 ?? ?? ?? ?? }  // Xor ecx + Call kernel function

    condition:
        any of them
}