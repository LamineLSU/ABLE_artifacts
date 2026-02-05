rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 D8 50 8B 4D 08 } //Trace 3, pushing eax, then ecx
        $pattern1 = { E8 C1 FF FF FF 59 FF 75 08 } //Trace //1 & //2, Call to 00427AD7h and pop ecx
        $pattern2 = { FF 35 10 93 52 00 FF 15 9C C2 4C 00 } //Trace //4 & //6, push dword ptr [00529310h] and call dword ptr [004CC29Ch]

    condition:
        any of them
}