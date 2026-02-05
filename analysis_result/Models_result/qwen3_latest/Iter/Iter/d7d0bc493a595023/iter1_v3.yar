rule EvasionCheck
{
    meta:
        description = "Detects evasion by identifying the use of ___crtCorExitProcess"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Researcher"
        date = "2025-04-05"
    strings:
        $a = { FF 75 08 E8 C1 FF FF FF } // push dword [ebp+08h], call ___crtCorExitProcess
        $b = { 59 FF 75 08 FF 15 68 F3 20 00 } // pop ecx, push dword [ebp+08h], call ExitProcess
        $c = { 55 8B EC FF 75 08 E8 C1 FF FF FF } // push ebp, mov ebp, push dword [ebp+08h], call ___crtCorExitProcess
    condition:
        any of them
}