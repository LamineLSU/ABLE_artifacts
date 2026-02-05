rule MaliciousBehavior
{
    meta:
        description = "Detects evasion behavior through indirect calls and suspicious memory manipulation"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Analyst"

    strings:
        $a = { 8B 56 ?? 83 C4 ?? 52 FF D0 }  // mov edx, [esi+??], add esp, ??, push edx, call eax
        $b = { 50 56 E8 ?? ?? ?? ?? }         // push eax, push esi, call ?? (indirect jump)
        $c = { 83 C4 ?? 52 FF D0 }            // add esp, ??, push edx, call eax

    condition:
        all of them
}