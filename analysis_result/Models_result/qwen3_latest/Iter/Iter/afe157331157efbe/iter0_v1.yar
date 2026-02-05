rule PotentialExecutionPattern
{
    meta:
        description = "Detects potential code execution or memory access patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $pattern0 = { FF 75 08 E8 ?? ?? ?? ?? 59 }  // push [ebp+08h], call (offset), pop ecx
        $pattern1 = { FF 75 08 FF 15 ?? ?? ?? ?? }    // push [ebp+08h], call (address)
        $pattern2 = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? }  // push ebp, mov ebp, push [ebp+08h], call (offset)

    condition:
        any of them
}