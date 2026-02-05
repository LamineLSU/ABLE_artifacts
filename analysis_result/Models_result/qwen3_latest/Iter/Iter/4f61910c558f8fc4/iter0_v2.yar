rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 53 FF 15 ?? ?? ?? ?? } // Push EAX + Push EBX + Call (context before ExitProcess call)
        $pattern1 = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? } // Push EBP + Mov EBP + Push [EBP+08h] + Call (context before indirect call)
        $pattern2 = { 55 8B EC FF 75 08 FF 15 ?? ?? ?? ?? } // Push EBP + Mov EBP + Push [EBP+08h] + Call (context before direct call)

    condition:
        any of them
}