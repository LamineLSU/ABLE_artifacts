rule SandboxCheck_ExitProcess
{
    meta:
        description = "Detects sandbox check by attempting to call ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,count=0"
        author = "Cybersecurity Analyst"
        date = "2023-10-15"
    strings:
        $a = { 8B 55 ?? 8B 06 ?? 83 C4 ?? 52 FF D0 } // MOV EDX, [EBP+??], MOV EAX, [ESI+??], ADD ESP, ??, PUSH EDX, CALL EAX
    condition:
        $a
}