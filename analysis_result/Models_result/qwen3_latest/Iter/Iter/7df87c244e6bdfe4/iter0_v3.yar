rule MaliciousFunctionPrologueAndExitCall
{
    meta:
        description = "Detects a function prologue followed by a potential exit call, indicating evasion logic."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2025-03-15"

    strings:
        $pattern0 = { FF 75 08 E8 ?? ?? ?? ?? 59 }  // push [ebp+08h], call (offset), pop ecx
        $pattern1 = { FF 75 08 FF 15 ?? ?? ?? ?? } // push [ebp+08h], call to ExitProcess (address)
        $pattern2 = { 55 8B EC FF 75 08 }            // push ebp, mov ebp, push [ebp+08h]

    condition:
        any of ($pattern0, $pattern1, $pattern2)
}