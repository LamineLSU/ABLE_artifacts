rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule for ExitProcess and ___crtCorExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 ?? ?? ?? ?? }  // Push [ebp+08h] followed by call to ___crtCorExitProcess
        $pattern1 = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }  // Pop ecx, push [ebp+08h], call to ExitProcess
        $pattern2 = { 55 8B EC FF 75 08 }  // Push ebp, mov ebp, push [ebp+08h]

    condition:
        any of them
}