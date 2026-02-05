rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific memory operations"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5A 8B CE E8 FF7508 push dword ptr [ebp+08h] }  # Targets the memory push operation
        $pattern1 = { C8 FF E8C8FFFFFF skip call }               # Skips the sandbox check call
        $pattern2 = { FB EC 8A 8B 45 mov edi, edi }            # Modifies the instruction sequence to bypass detection
    condition:
        any of them
}