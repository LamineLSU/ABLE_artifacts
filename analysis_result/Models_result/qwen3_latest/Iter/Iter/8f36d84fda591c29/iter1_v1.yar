rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D2 55 8B EC 56 } // CALL EDX, PUSH EBP, MOV EBP, ESP, PUSH ESI
        $pattern1 = { FF D2 55 8B EC 57 } // CALL EDX, PUSH EBP, MOV EBP, ESP, PUSH EDI
        $pattern2 = { 8B 45 08 8B 88 40 08 00 00 } // MOV EAX, [EBP+08], MOV ECX, [EAX+0840]

    condition:
        any of them
}