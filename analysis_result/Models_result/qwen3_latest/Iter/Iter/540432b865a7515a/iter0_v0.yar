rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Push ebx + Call to ExitProcess
        $pattern1 = { 8B CE E8 ?? ?? ?? ?? }  // Mov ecx, esi + Call to evasion check
        $pattern2 = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Push ebp+08h + Call to sandbox check

    condition:
        any of them
}