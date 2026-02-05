rule EvasionCheck
{
    meta:
        description = "Detects evasion checks via indirect calls and register-based calls"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"

    strings:
        $a = { 52 FF D0 5E 5D C3 }  // PUSH EDX, CALL EAX, POP ESI, POP EBP, RET
        $b = { 50 E8 ?? ?? ?? ?? 8B 55 0C }  // PUSH EAX, CALL (offset), MOV EDX, [EBP+0C]
        $c = { E8 ?? ?? ?? ?? 8B 55 0C }  // CALL (offset), MOV EDX, [EBP+0C]

    condition:
        $a or $b or $c
}