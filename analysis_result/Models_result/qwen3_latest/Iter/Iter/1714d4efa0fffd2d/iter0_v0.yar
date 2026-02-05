rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Push EBX + Call ExitProcess
        $pattern1 = { 85 C0 74 12 6A 5B }      // Test EAX + JE + Push 0x5B
        $pattern2 = { 8B CE E8 ?? ?? ?? ?? }  // MOV ECX + Call (RVA)

    condition:
        all of them
}