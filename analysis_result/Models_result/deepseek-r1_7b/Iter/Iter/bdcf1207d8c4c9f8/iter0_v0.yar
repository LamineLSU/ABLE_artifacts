rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8BFF 55 8BEC FF75 08?? } // mov edi, push ebp, mov ebp, push dword ptr [ebp+08h]
        $pattern1 = { E8C8 ?? 59 } // call dword ptr, pop ecx
        $pattern2 = { E8C8 ?? 59 FF75 08?? 0F85 } // additional instructions from the second exit process
    condition:
        any of them
}