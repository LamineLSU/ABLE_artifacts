rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? }  // Push eax + Call + Jmp (TRACE //1)
        $pattern1 = { BA 21 05 00 00 53 FF 15 ?? ?? ?? ?? }      // Mov edx + Push ebx + Call (TRACE //2)
        $pattern2 = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? }      // Push ebp + Mov ebp + Push + Call (TRACE //3)

    condition:
        any of them
}