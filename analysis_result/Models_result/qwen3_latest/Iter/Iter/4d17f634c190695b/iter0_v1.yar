rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = 83 F8 11 74 05 8B C0 FC 85 C9 0B C0  # CMP EAX,11h + JE + MOV EAX + CLD + TEST ECX
        $pattern1 = 83 7D FC 00 74 2F 90 8A C0 68 C0 9E E6 05  # CMP [ebp-4],0 + JE 00401060 + NOP + MOV AL + PUSH
        $pattern2 = 83 7D FC 00 75 08 6A 00 FF 15 2C 64 45 00  # CMP [ebp-4],0 + JNE 00401099 + PUSH 0 + CALL ExitProcess

    condition:
        any of them
}