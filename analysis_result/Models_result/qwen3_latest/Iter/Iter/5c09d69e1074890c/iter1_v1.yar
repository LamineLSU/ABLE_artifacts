rule ExitProcess_Call_Detection
{
    meta:
        description = "Detects code leading to a call to ExitProcess (or similar system call)."
        cape_options = "bp0=$a1+0,action0=skip,bp1=$a2+0,action1=skip,bp2=$a3+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
        tags = "malware", "exitprocess", "systemcall"

    strings:
        $a1 = { 8B 55 0C 8B 06 83 C4 14 52 FF D0 } // MOV EDX, [EBP+0C], MOV EAX, [ESI], ADD ESP, 14, PUSH EDX, CALL EAX
        $a2 = { 50 E8 ?? ?? ?? ?? 8B 55 0C }       // PUSH EAX, CALL (with offset), MOV EDX, [EBP+0C]
        $a3 = { 8B 06 83 C4 14 52 FF D0 }          // MOV EAX, [ESI], ADD ESP, 14, PUSH EDX, CALL EAX

    condition:
        (all of $a1) or (all of $a2) or (all of $a3)
}