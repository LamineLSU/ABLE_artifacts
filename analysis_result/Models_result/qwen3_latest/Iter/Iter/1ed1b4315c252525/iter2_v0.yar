rule Bypass_Sample
{
    meta:
        description = "Evasion bypass pattern based on ExitProcess and CRT exit function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 }  // push ebp, mov ebp, esp, push [ebp+08h]
        $pattern1 = { FF 75 08 E8 ?? ?? ?? ?? }  // push [ebp+08h], call (offset replaced)
        $pattern2 = { 59 FF 15 ?? ?? ?? ?? }  // pop ecx, call (address replaced)

    condition:
        any of them
}