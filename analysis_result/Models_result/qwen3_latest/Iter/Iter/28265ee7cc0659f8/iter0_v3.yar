rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 ?? ?? ?? ?? }  // Test EAX + JNE + PUSH + POP + MOV + CALL
        $pattern1 = { FF 15 ?? ?? ?? ?? 33 FF 8B C7 EB 03 8D 43 01 }  // CALL dword + XOR EDI + MOV EAX, EDI + JMP + LEA
        $pattern2 = { E8 C8 FF FF 55 8B EC FF 75 08 FF 15 ?? ?? ?? ?? }  // CALL + PUSH EBP + MOV EBP, ESP + PUSH [EBP+08h] + CALL dword

    condition:
        any of them
}